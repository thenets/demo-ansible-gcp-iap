# Copyright (c) 2012, Michael DeHaan <michael.dehaan@gmail.com>
# Copyright 2015 Abhijit Menon-Sen <ams@2ndQuadrant.com>
# Copyright 2017 Toshio Kuratomi <tkuratomi@ansible.com>
# Copyright (c) 2017 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Based on https://github.com/ansible/ansible/blob/devel/lib/ansible/plugins/connection/ssh.py

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
    name: gcp_ssh
    short_description: connect via gcloud compute ssh/scp client binary
    description:
        - This connection plugin allows ansible to communicate to the target machines via normal gcloud compute ssh/scp command line.
    author:
        - "Dominique Vernier (@itdove)"
        - "Luiz Costa (@thenets)"
    extends_documentation_fragment:
        - connection_pipelining
    options:
      host:
          description: instance name to connect to.
          default: inventory_hostname
          vars:
            - name: inventory_hostname
            - name: ansible_host
            - name: ansible_ssh_host
            - name: delegated_vars['ansible_host']
            - name: delegated_vars['ansible_ssh_host']
      remote_user:
          description:
              - User name with which to login to the remote server, normally set by the remote_user keyword.
              - If no user is supplied, Ansible will let the SSH client binary choose the user as it normally.
          ini:
            - section: defaults
              key: remote_user
          env:
            - name: ANSIBLE_REMOTE_USER
          vars:
            - name: ansible_user
            - name: ansible_ssh_user
          cli:
            - name: user
          keyword:
            - name: remote_user
      pipelining:
          env:
            - name: ANSIBLE_PIPELINING
            - name: ANSIBLE_SSH_PIPELINING
          ini:
            - section: defaults
              key: pipelining
            - section: connection
              key: pipelining
            - section: ssh_connection
              key: pipelining
          vars:
            - name: ansible_pipelining
            - name: ansible_ssh_pipelining
      zone:
          description: the zone where the instance reside
          vars:
            - name: gcp_zone
      gcloud_binary:
          description: path to the gcloud binary
          vars:
            - name: gcp_gcloud_binary
          default: gcloud
      compute_ssh_flags:
          description: flags to pass to the gcloud compute ssh command-line
          default: '--tunnel-through-iap --no-user-output-enabled --quiet'
          vars:
            - name: gcp_compute_ssh_flags
      compute_ssh_args:
          description: arguments to pass to the underlying ssh command
          vars:
            - name: gcp_compute_ssh_args
      compute_scp_flags:
          description: flags to pass to the gcloud compute scp command-line
          default: '--tunnel-through-iap --quiet'
          vars:
            - name: gcp_compute_scp_flags
      reconnection_retries:
          description:
            - Number of attempts to connect.
            - Ansible retries connections only if it gets an SSH error with a return code of 255.
            - Any errors with return codes other than 255 indicate an issue with program execution.
          default: 3
          type: integer
          env:
            - name: ANSIBLE_SSH_RETRIES
          ini:
            - section: connection
              key: retries
            - section: ssh_connection
              key: retries
          vars:
            - name: ansible_ssh_retries
"""

EXAMPLES = r"""
# Making use of Dynamic Inventory Plugin
# =======================================
# google.cloud.gcp_compute (Dynamic Inventory - Linux)
# This will return the name of hosts
# plugin: "google.cloud.gcp_compute"
# auth_kind: "application"
# hostnames:
#  - name
# compose can be use to set the plugin vars
- name: Get hostname and user
  hosts: all
  connection: redhat.ansible_on_clouds.gcp_ssh
  remote_user: awx
  vars:
    gcp_compute_ssh_flags: "--tunnel-through-iap --no-user-output-enabled --quiet"
    gcp_zone: "us-east1-b"
    gcp_compute_scp_flags: "--tunnel-through-iap --quiet"
  tasks:
    - name: Get hostname
      ansible.builtin.command:
        cmd: "hostname"
      register: hostname
    - name: Show hostname
      ansible.builtin.debug:
        msg:
        - "hostname: {{ hostname.stdout_lines }}"
"""

import fcntl
import os
import pty
import re
import shlex
import subprocess
import time

from functools import wraps
from ansible import constants as C
from ansible.errors import (
    AnsibleAuthenticationFailure,
    AnsibleConnectionFailure,
    AnsibleError,
    AnsibleFileNotFound,
)
from ansible.module_utils.compat import selectors
from ansible.module_utils.six import text_type, binary_type
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.plugins.connection import ConnectionBase
from ansible.plugins.shell.powershell import _parse_clixml
from ansible.utils.display import Display

display = Display()


b_NOT_SSH_ERRORS = (
    b"Traceback (most recent call last):",  # Python-2.6 when there's an exception
    # while invoking a script via -m
    b"PHP Parse error:",  # Php always returns error 255
)

SSHPASS_AVAILABLE = None


class AnsibleControlPersistBrokenPipeError(AnsibleError):
    """ControlPersist broken pipe"""

    pass


def _handle_error(
    remaining_retries, command, return_tuple, no_log, host, display=display
):
    if return_tuple[0] == 255:
        SSH_ERROR = True
        for signature in b_NOT_SSH_ERRORS:
            if signature in return_tuple[1]:
                SSH_ERROR = False
                break

        if SSH_ERROR:
            msg = "Failed to connect to the host via ssh:"
            if no_log:
                msg = "{0} <error censored due to no log>".format(msg)
            else:
                msg = "{0} {1}".format(msg, to_native(return_tuple[2]).rstrip())
            raise AnsibleConnectionFailure(msg)

    # For other errors, no exception is raised so the connection is retried
    # and we only log the messages
    if 1 <= return_tuple[0] <= 254:
        msg = "Failed to connect to the host via ssh:"
        if no_log:
            msg = "{0} <error censored due to no log>".format(msg)
        else:
            msg = "{0} {1}".format(msg, to_text(return_tuple[2]).rstrip())
        display.vvv(msg, host=host)


def _ssh_retry(func):
    """
    Decorator to retry ssh/scp/sftp in the case of a connection failure
    Will retry if:
    * an exception is caught
    * ssh returns 255
    Will not retry if
    * sshpass returns 5 (invalid password, to prevent account lockouts)
    * remaining_tries is < 2
    * retries limit reached
    """

    @wraps(func)
    def wrapped(self, *args, **kwargs):
        remaining_tries = int(self.get_option("reconnection_retries")) + 1
        cmd_summary = "%s..." % to_text(args[0])
        for attempt in range(remaining_tries):
            cmd = args[0]
            try:
                try:
                    return_tuple = func(self, *args, **kwargs)
                    if self._play_context.no_log:
                        display.vvv(
                            "rc=%s, stdout and stderr censored due to no log"
                            % return_tuple[0],
                            host=self.host,
                        )
                    else:
                        display.vvv(return_tuple, host=self.host)
                    # 0 = success
                    # 1-254 = remote command return code
                    # 255 could be a failure from the ssh command itself
                except AnsibleControlPersistBrokenPipeError:
                    # Retry one more time because of the ControlPersist broken pipe (see #16731)
                    cmd = args[0]
                    display.vvv("RETRYING BECAUSE OF CONTROLPERSIST BROKEN PIPE")
                    return_tuple = func(self, *args, **kwargs)

                remaining_retries = remaining_tries - attempt - 1
                _handle_error(
                    remaining_retries,
                    cmd,
                    return_tuple,
                    self._play_context.no_log,
                    self.host,
                )

                break

            # 5 = Invalid/incorrect password from sshpass
            except AnsibleAuthenticationFailure:
                # Raising this exception, which is subclassed from AnsibleConnectionFailure
                # prevents further retries
                raise

            except (AnsibleConnectionFailure, Exception) as e:
                if attempt == remaining_tries - 1:
                    raise
                else:
                    pause = 2**attempt - 1
                    if pause > 30:
                        pause = 30

                    if isinstance(e, AnsibleConnectionFailure):
                        msg = (
                            "ssh_retry: attempt: %d, ssh return code is 255. cmd (%s), pausing for %d seconds"
                            % (attempt + 1, cmd_summary, pause)
                        )
                    else:
                        msg = (
                            "ssh_retry: attempt: %d, caught exception(%s) from cmd (%s), "
                            "pausing for %d seconds"
                            % (attempt + 1, to_text(e), cmd_summary, pause)
                        )

                    display.vv(msg, host=self.host)

                    time.sleep(pause)
                    continue

        return return_tuple

    return wrapped


class Connection(ConnectionBase):
    """ssh based connections"""

    transport = "ssh"
    has_pipelining = True

    def __init__(self, *args, **kwargs):
        super(Connection, self).__init__(*args, **kwargs)

        self.remote_user = self._play_context.remote_user
        self.host = self._play_context.remote_addr
        self.user = self._play_context.remote_user

    # The connection is created by running ssh/scp/sftp from the exec_command,
    # put_file, and fetch_file methods, so we don't need to do any connection
    # management here.

    def _connect(self):
        return self

    @staticmethod
    def _persistence_controls(b_command):
        """
        Takes a command array and scans it for ControlPersist and ControlPath
        settings and returns two booleans indicating whether either was found.
        This could be smarter, e.g. returning false if ControlPersist is 'no',
        but for now we do it simple way.
        """

        controlpersist = False
        controlpath = False

        for b_arg in (a.lower() for a in b_command):
            if b"controlpersist" in b_arg:
                controlpersist = True
            elif b"controlpath" in b_arg:
                controlpath = True

        return controlpersist, controlpath

    def _add_args(self, b_command, b_args, explanation):
        """
        Adds arguments to the ssh command and displays a caller-supplied explanation of why.
        :arg b_command: A list containing the command to add the new arguments to.
            This list will be modified by this method.
        :arg b_args: An iterable of new arguments to add.  This iterable is used
            more than once so it must be persistent (ie: a list is okay but a
            StringIO would not)
        :arg explanation: A text string containing explaining why the arguments
            were added.  It will be displayed with a high enough verbosity.
        .. note:: This function does its work via side-effect.  The b_command list has the new arguments appended.
        """
        display.vvvvv(
            "SSH: %s: (%s)" % (explanation, ")(".join(to_text(a) for a in b_args)),
            host=self._play_context.remote_addr,
        )
        b_command += b_args

    def _build_command(self, binary, *other_args):
        """
        Takes a binary (ssh, scp, sftp) and optional extra arguments and returns
        a command line as an array that can be passed to subprocess.Popen.
        """

        if self.get_option("gcloud_binary"):
            gcloud_binary = self.get_option("gcloud_binary")

        b_command = []
        b_command += [to_bytes(gcloud_binary, errors="surrogate_or_strict")]
        # b_command += [to_bytes("--verbosity", errors="surrogate_or_strict")]
        # b_command += [to_bytes("debug", errors="surrogate_or_strict")]
        b_command += [to_bytes("compute", errors="surrogate_or_strict")]
        if binary == "ssh":
            b_command += [to_bytes("ssh", errors="surrogate_or_strict")]
        else:
            b_command += [to_bytes("scp", errors="surrogate_or_strict")]

        # TODO currently not supported by `gcloud` CLI
        # if display.verbosity > 3:
        #     b_command.append(b"-vvv")

        # Now we add various arguments controlled by configuration file settings
        # (e.g. host_key_checking) or inventory variables (ansible_ssh_port) or
        # a combination thereof.

        # Add in any common or binary-specific arguments from the PlayContext
        # (i.e. inventory or task settings or overrides on the command line).

        if self.get_option("zone"):
            zone = self.get_option("zone")
            b_command.append(b"--zone")
            b_command.append(to_bytes(zone, errors="surrogate_or_strict"))
        if binary == "ssh":
            compute_ssh_flags = self.get_option("compute_ssh_flags")
            if compute_ssh_flags:
                b_args = [
                    to_bytes(a, errors="surrogate_or_strict")
                    for a in self._split_ssh_args(compute_ssh_flags)
                ]
                self._add_args(b_command, b_args, "ansible.cfg set compute_ssh_flags")
            if self.remote_user:
                b_command.append(
                    to_bytes(
                        "%s@%s" % (self.remote_user, self.host),
                        errors="surrogate_or_strict",
                    )
                )
            else:
                b_command.append(to_bytes(self.host, errors="surrogate_or_strict"))
            b_command.append(b"--")
            compute_ssh_args = self.get_option("compute_ssh_args")
            if compute_ssh_args:
                b_args = [
                    to_bytes(a, errors="surrogate_or_strict")
                    for a in self._split_ssh_args(compute_ssh_args)
                ]
                self._add_args(b_command, b_args, "ansible.cfg set compute_ssh_flags")
            b_command.append(b"-C")
            # Finally, we add any caller-supplied extras.
            if other_args:
                b_command += [to_bytes(a) for a in other_args[1:]]
        else:
            compute_scp_flags = self.get_option("compute_scp_flags")
            if compute_scp_flags:
                b_args = [
                    to_bytes(a, errors="surrogate_or_strict")
                    for a in self._split_ssh_args(compute_scp_flags)
                ]
                self._add_args(b_command, b_args, "ansible.cfg set compute_scp_flags")

            # Loop on all source files
            for other_arg in other_args[:-1]:
                b_command.append(to_bytes(other_arg, errors="surrogate_or_strict"))
            # Add user if need on destination file
            if self.remote_user:
                b_command.append(
                    to_bytes(
                        "%s@%s" % (self.remote_user, other_args[len(other_args) - 1]),
                        errors="surrogate_or_strict",
                    )
                )
            else:
                b_command.append(
                    to_bytes(
                        other_args[len(other_args) - 1], errors="surrogate_or_strict"
                    )
                )

        return b_command

    def _send_initial_data(self, fh, in_data, ssh_process):
        """
        Writes initial data to the stdin filehandle of the subprocess and closes
        it. (The handle must be closed; otherwise, for example, "sftp -b -" will
        just hang forever waiting for more commands.)
        """

        display.debug("Sending initial data")

        try:
            fh.write(to_bytes(in_data))
            fh.close()
        except (OSError, IOError) as e:
            # The ssh connection may have already terminated at this point, with a more useful error
            # Only raise AnsibleConnectionFailure if the ssh process is still alive
            time.sleep(0.001)
            ssh_process.poll()
            if getattr(ssh_process, "returncode", None) is None:
                raise AnsibleConnectionFailure(
                    'Data could not be sent to remote host "%s". Make sure this host can be reached '
                    "over ssh: %s" % (self.host, to_native(e)),
                    orig_exc=e,
                )

        display.debug("Sent initial data (%d bytes)" % len(in_data))

    # Used by _run() to kill processes on failures
    @staticmethod
    def _terminate_process(p):
        """Terminate a process, ignoring errors"""
        try:
            p.terminate()
        except (OSError, IOError):
            pass

    # This is separate from _run() because we need to do the same thing for stdout
    # and stderr.
    def _examine_output(self, source, state, b_chunk, sudoable):
        """
        Takes a string, extracts complete lines from it, tests to see if they
        are a prompt, error message, etc., and sets appropriate flags in self.
        Prompt and success lines are removed.
        Returns the processed (i.e. possibly-edited) output and the unprocessed
        remainder (to be processed with the next chunk) as strings.
        """

        output = []
        for b_line in b_chunk.splitlines(True):
            display_line = to_text(b_line).rstrip("\r\n")
            suppress_output = False

            # display.debug("Examining line (source=%s, state=%s): '%s'" % (source, state, display_line))
            if self.become.expect_prompt() and self.become.check_password_prompt(
                b_line
            ):
                display.debug(
                    "become_prompt: (source=%s, state=%s): '%s'"
                    % (source, state, display_line)
                )
                self._flags["become_prompt"] = True
                suppress_output = True
            elif self.become.success and self.become.check_success(b_line):
                display.debug(
                    "become_success: (source=%s, state=%s): '%s'"
                    % (source, state, display_line)
                )
                self._flags["become_success"] = True
                suppress_output = True
            elif sudoable and self.become.check_incorrect_password(b_line):
                display.debug(
                    "become_error: (source=%s, state=%s): '%s'"
                    % (source, state, display_line)
                )
                self._flags["become_error"] = True
            elif sudoable and self.become.check_missing_password(b_line):
                display.debug(
                    "become_nopasswd_error: (source=%s, state=%s): '%s'"
                    % (source, state, display_line)
                )
                self._flags["become_nopasswd_error"] = True

            if not suppress_output:
                output.append(b_line)

        # The chunk we read was most likely a series of complete lines, but just
        # in case the last line was incomplete (and not a prompt, which we would
        # have removed from the output), we retain it to be processed with the
        # next chunk.

        remainder = b""
        if output and not output[-1].endswith(b"\n"):
            remainder = output[-1]
            output = output[:-1]

        return b"".join(output), remainder

    def _bare_run(self, cmd, in_data, sudoable=True, checkrc=True):
        """
        Starts the command and communicates with it until it ends.
        """

        # We don't use _shell.quote as this is run on the controller and independent from the shell plugin chosen
        display_cmd = " ".join(shlex.quote(to_text(c)) for c in cmd)
        display.vvv("SSH: EXEC {0}".format(display_cmd), host=self.host)

        # Start the given command. If we don't need to pipeline data, we can try
        # to use a pseudo-tty (ssh will have been invoked with -tt). If we are
        # pipelining data, or can't create a pty, we fall back to using plain
        # old pipes.

        p = None

        if isinstance(cmd, (text_type, binary_type)):
            cmd = to_bytes(cmd)
        else:
            cmd = list(map(to_bytes, cmd))

        if not in_data:
            try:
                # Make sure stdin is a proper pty to avoid tcgetattr errors
                master, slave = pty.openpty()
                p = subprocess.Popen(
                    cmd, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                stdin = os.fdopen(master, "wb", 0)
                os.close(slave)
            except (OSError, IOError):
                p = None

        if not p:
            try:
                p = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                stdin = p.stdin
            except (OSError, IOError) as e:
                raise AnsibleError(
                    "Unable to execute ssh command line on a controller due to: %s"
                    % to_native(e)
                )

        #
        # SSH state machine
        #

        # Now we read and accumulate output from the running process until it
        # exits. Depending on the circumstances, we may also need to write an
        # escalation password and/or pipelined input to the process.

        states = [
            "awaiting_prompt",
            "awaiting_escalation",
            "ready_to_send",
            "awaiting_exit",
        ]

        # Are we requesting privilege escalation? Right now, we may be invoked
        # to execute sftp/scp with sudoable=True, but we can request escalation
        # only when using ssh. Otherwise we can send initial data straightaway.

        state = states.index("ready_to_send")
        if to_bytes("ssh") in cmd and sudoable:
            prompt = getattr(self.become, "prompt", None)
            if prompt:
                # We're requesting escalation with a password, so we have to
                # wait for a password prompt.
                state = states.index("awaiting_prompt")
                display.debug(
                    "Initial state: %s: %s" % (states[state], to_text(prompt))
                )
            elif self.become and self.become.success:
                # We're requesting escalation without a password, so we have to
                # detect success/failure before sending any initial data.
                state = states.index("awaiting_escalation")
                display.debug(
                    "Initial state: %s: %s"
                    % (states[state], to_text(self.become.success))
                )

        # We store accumulated stdout and stderr output from the process here,
        # but strip any privilege escalation prompt/confirmation lines first.
        # Output is accumulated into tmp_*, complete lines are extracted into
        # an array, then checked and removed or copied to stdout or stderr. We
        # set any flags based on examining the output in self._flags.

        b_stdout = b_stderr = b""
        b_tmp_stdout = b_tmp_stderr = b""

        self._flags = dict(
            become_prompt=False,
            become_success=False,
            become_error=False,
            become_nopasswd_error=False,
        )

        # select timeout should be longer than the connect timeout, otherwise
        # they will race each other when we can't connect, and the connect
        # timeout usually fails
        timeout = 2 + self._play_context.timeout
        for fd in (p.stdout, p.stderr):
            fcntl.fcntl(
                fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK
            )

        # TODO: bcoca would like to use SelectSelector() when open
        # filehandles is low, then switch to more efficient ones when higher.
        # select is faster when filehandles is low.
        selector = selectors.DefaultSelector()
        selector.register(p.stdout, selectors.EVENT_READ)
        selector.register(p.stderr, selectors.EVENT_READ)

        # If we can send initial data without waiting for anything, we do so
        # before we start polling
        if states[state] == "ready_to_send" and in_data:
            self._send_initial_data(stdin, in_data, p)
            state += 1

        try:
            while True:
                poll = p.poll()
                events = selector.select(timeout)

                # We pay attention to timeouts only while negotiating a prompt.

                if not events:
                    # We timed out
                    if state <= states.index("awaiting_escalation"):
                        # If the process has already exited, then it's not really a
                        # timeout; we'll let the normal error handling deal with it.
                        if poll is not None:
                            break
                        self._terminate_process(p)
                        raise AnsibleError(
                            "Timeout (%ds) waiting for privilege escalation prompt: %s"
                            % (timeout, to_native(b_stdout))
                        )

                # Read whatever output is available on stdout and stderr, and stop
                # listening to the pipe if it's been closed.

                for key, event in events:
                    if key.fileobj == p.stdout:
                        b_chunk = p.stdout.read()
                        if b_chunk == b"":
                            # stdout has been closed, stop watching it
                            selector.unregister(p.stdout)
                            # When ssh has ControlMaster (+ControlPath/Persist) enabled, the
                            # first connection goes into the background and we never see EOF
                            # on stderr. If we see EOF on stdout, lower the select timeout
                            # to reduce the time wasted selecting on stderr if we observe
                            # that the process has not yet existed after this EOF. Otherwise
                            # we may spend a long timeout period waiting for an EOF that is
                            # not going to arrive until the persisted connection closes.
                            timeout = 1
                        b_tmp_stdout += b_chunk
                        display.debug(
                            "stdout chunk (state=%s):\n>>>%s<<<\n"
                            % (state, to_text(b_chunk))
                        )
                    elif key.fileobj == p.stderr:
                        b_chunk = p.stderr.read()
                        if b_chunk == b"":
                            # stderr has been closed, stop watching it
                            selector.unregister(p.stderr)
                        b_tmp_stderr += b_chunk
                        display.debug(
                            "stderr chunk (state=%s):\n>>>%s<<<\n"
                            % (state, to_text(b_chunk))
                        )

                # We examine the output line-by-line until we have negotiated any
                # privilege escalation prompt and subsequent success/error message.
                # Afterwards, we can accumulate output without looking at it.

                if state < states.index("ready_to_send"):
                    if b_tmp_stdout:
                        b_output, b_unprocessed = self._examine_output(
                            "stdout", states[state], b_tmp_stdout, sudoable
                        )
                        b_stdout += b_output
                        b_tmp_stdout = b_unprocessed

                    if b_tmp_stderr:
                        b_output, b_unprocessed = self._examine_output(
                            "stderr", states[state], b_tmp_stderr, sudoable
                        )
                        b_stderr += b_output
                        b_tmp_stderr = b_unprocessed
                else:
                    b_stdout += b_tmp_stdout
                    b_stderr += b_tmp_stderr
                    b_tmp_stdout = b_tmp_stderr = b""

                # If we see a privilege escalation prompt, we send the password.
                # (If we're expecting a prompt but the escalation succeeds, we
                # didn't need the password and can carry on regardless.)

                if states[state] == "awaiting_prompt":
                    if self._flags["become_prompt"]:
                        display.debug("Sending become_password in response to prompt")
                        become_pass = self.become.get_option(
                            "become_pass", playcontext=self._play_context
                        )
                        stdin.write(
                            to_bytes(become_pass, errors="surrogate_or_strict") + b"\n"
                        )
                        # On python3 stdin is a BufferedWriter, and we don't have a guarantee
                        # that the write will happen without a flush
                        stdin.flush()
                        self._flags["become_prompt"] = False
                        state += 1
                    elif self._flags["become_success"]:
                        state += 1

                # We've requested escalation (with or without a password), now we
                # wait for an error message or a successful escalation.

                if states[state] == "awaiting_escalation":
                    if self._flags["become_success"]:
                        display.vvv("Escalation succeeded")
                        self._flags["become_success"] = False
                        state += 1
                    elif self._flags["become_error"]:
                        display.vvv("Escalation failed")
                        self._terminate_process(p)
                        self._flags["become_error"] = False
                        raise AnsibleError("Incorrect %s password" % self.become.name)
                    elif self._flags["become_nopasswd_error"]:
                        display.vvv("Escalation requires password")
                        self._terminate_process(p)
                        self._flags["become_nopasswd_error"] = False
                        raise AnsibleError("Missing %s password" % self.become.name)
                    elif self._flags["become_prompt"]:
                        # This shouldn't happen, because we should see the "Sorry,
                        # try again" message first.
                        display.vvv("Escalation prompt repeated")
                        self._terminate_process(p)
                        self._flags["become_prompt"] = False
                        raise AnsibleError("Incorrect %s password" % self.become.name)

                # Once we're sure that the privilege escalation prompt, if any, has
                # been dealt with, we can send any initial data and start waiting
                # for output.

                if states[state] == "ready_to_send":
                    if in_data:
                        self._send_initial_data(stdin, in_data, p)
                    state += 1

                # Now we're awaiting_exit: has the child process exited? If it has,
                # and we've read all available output from it, we're done.

                if poll is not None:
                    if not selector.get_map() or not events:
                        break
                    # We should not see further writes to the stdout/stderr file
                    # descriptors after the process has closed, set the select
                    # timeout to gather any last writes we may have missed.
                    timeout = 0
                    continue

                # If the process has not yet exited, but we've already read EOF from
                # its stdout and stderr (and thus no longer watching any file
                # descriptors), we can just wait for it to exit.

                elif not selector.get_map():
                    display.vvv(
                        "SSH: wait process to exit {0}".format(display_cmd),
                        host=self.host,
                    )
                    p.wait()
                    break

                # Otherwise there may still be outstanding data to read.
                display.vvv("SSH: Waiting data {0}".format(display_cmd), host=self.host)

        finally:
            selector.close()
            # close stdin, stdout, and stderr after process is terminated and
            # stdout/stderr are read completely (see also issues #848, #64768).
            stdin.close()
            p.stdout.close()
            p.stderr.close()

        if C.HOST_KEY_CHECKING:
            if cmd[0] == b"sshpass" and p.returncode == 6:
                raise AnsibleError(
                    "Using a SSH password instead of a key is not possible because Host Key checking is enabled and sshpass does not support "
                    "this.  Please add this host's fingerprint to your known_hosts file to manage this host."
                )

        controlpersisterror = (
            b"Bad configuration option: ControlPersist" in b_stderr
            or b"unknown configuration option: ControlPersist" in b_stderr
        )
        if p.returncode != 0 and controlpersisterror:
            raise AnsibleError(
                'using -c ssh on certain older ssh versions may not support ControlPersist, set ANSIBLE_SSH_ARGS="" '
                "(or ssh_args in [ssh_connection] section of the config file) before running again"
            )

        # If we find a broken pipe because of ControlPersist timeout expiring (see #16731),
        # we raise a special exception so that we can retry a connection.
        controlpersist_broken_pipe = (
            b"mux_client_hello_exchange: write packet: Broken pipe" in b_stderr
        )
        if p.returncode == 255:
            additional = to_native(b_stderr)
            if controlpersist_broken_pipe:
                raise AnsibleControlPersistBrokenPipeError(
                    "Data could not be sent because of ControlPersist broken pipe: %s"
                    % additional
                )

            elif in_data and checkrc:
                raise AnsibleConnectionFailure(
                    'Data could not be sent to remote host "%s". Make sure this host can be reached over ssh: %s'
                    % (self.host, additional)
                )

        return (p.returncode, b_stdout, b_stderr)

    @_ssh_retry
    def _run(self, cmd, in_data, sudoable=True, checkrc=True):
        """Wrapper around _bare_run that retries the connection"""
        return self._bare_run(cmd, in_data, sudoable=sudoable, checkrc=checkrc)

    @_ssh_retry
    def _file_transport_command(self, in_path, out_path, sftp_action):
        # scp and sftp require square brackets for IPv6 addresses, but
        # accept them for hostnames and IPv4 addresses too.
        returncode = stdout = stderr = None
        scp = "scp"

        if sftp_action == "get":
            cmd = self._build_command(
                scp, "{0}:{1}".format(self.host, self._shell.quote(in_path)), out_path
            )
        else:
            cmd = self._build_command(
                scp, in_path, "{0}:{1}".format(self.host, self._shell.quote(out_path))
            )
        in_data = None
        (returncode, stdout, stderr) = self._bare_run(cmd, in_data, checkrc=False)

        # Check the return code and rollover to next method if failed
        if returncode == 0:
            return (returncode, stdout, stderr)
        else:
            display.warning(
                "scp transfer mechanism failed on %s. Use ANSIBLE_DEBUG=1 to see detailed information"
                % (self.host)
            )
            display.debug("%s" % to_text(stdout))
            display.debug("%s" % to_text(stderr))

        if returncode == 255:
            raise AnsibleConnectionFailure(
                "Failed to connect to the host: %s" % (to_native(stderr))
            )
        else:
            raise AnsibleError(
                "failed to transfer file to %s %s:\n%s\n%s"
                % (
                    to_native(in_path),
                    to_native(out_path),
                    to_native(stdout),
                    to_native(stderr),
                )
            )

    def _escape_win_path(self, path):
        """converts a Windows path to one that's supported by SFTP and SCP"""
        # If using a root path then we need to start with /
        prefix = ""
        if re.match(r"^\w{1}:", path):
            prefix = "/"

        # Convert all '\' to '/'
        return "%s%s" % (prefix, path.replace("\\", "/"))

    #
    # Main public methods
    #
    def exec_command(self, cmd, in_data=None, sudoable=True):
        """run a command on the remote host"""

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        self.host = self.get_option("host") or self._play_context.remote_addr

        display.vvv(
            "ESTABLISH SSH CONNECTION FOR USER: {0}".format(self.user), host=self.host
        )

        if getattr(self._shell, "_IS_WINDOWS", False):
            # Become method 'runas' is done in the wrapper that is executed,
            # need to disable sudoable so the bare_run is not waiting for a
            # prompt that will not occur
            sudoable = False

            # Make sure our first command is to set the console encoding to
            # utf-8, this must be done via chcp to get utf-8 (65001)
            cmd_parts = [
                "chcp.com",
                "65001",
                self._shell._SHELL_REDIRECT_ALLNULL,
                self._shell._SHELL_AND,
            ]
            cmd_parts.extend(
                self._shell._encode_script(
                    cmd, as_list=True, strict_mode=False, preserve_rc=False
                )
            )
            cmd = " ".join(cmd_parts)

        # we can only use tty when we are not pipelining the modules. piping
        # data into /usr/bin/python inside a tty automatically invokes the
        # python interactive-mode but the modules are not compatible with the
        # interactive-mode ("unexpected indent" mainly because of empty lines)

        ssh_executable = "ssh"

        args = (ssh_executable, self.host, cmd)

        cmd = self._build_command(*args)
        (returncode, stdout, stderr) = self._run(cmd, in_data, sudoable=sudoable)

        # When running on Windows, stderr may contain CLIXML encoded output
        if getattr(self._shell, "_IS_WINDOWS", False) and stderr.startswith(
            b"#< CLIXML"
        ):
            stderr = _parse_clixml(stderr)

        return (returncode, stdout, stderr)

    def put_file(self, in_path, out_path):
        """transfer a file from local to remote"""

        super(Connection, self).put_file(in_path, out_path)

        self.host = self.get_option("host") or self._play_context.remote_addr

        display.vvv("PUT {0} TO {1}".format(in_path, out_path), host=self.host)

        if not os.path.exists(to_bytes(in_path, errors="surrogate_or_strict")):
            raise AnsibleFileNotFound(
                "file or module does not exist: {0}".format(to_native(in_path))
            )

        if getattr(self._shell, "_IS_WINDOWS", False):
            out_path = self._escape_win_path(out_path)

        return self._file_transport_command(in_path, out_path, "put")

    def fetch_file(self, in_path, out_path):
        """fetch a file from remote to local"""

        super(Connection, self).fetch_file(in_path, out_path)

        self.host = self.get_option("host") or self._play_context.remote_addr

        display.vvv("FETCH {0} TO {1}".format(in_path, out_path), host=self.host)

        # need to add / if path is rooted
        if getattr(self._shell, "_IS_WINDOWS", False):
            in_path = self._escape_win_path(in_path)

        return self._file_transport_command(in_path, out_path, "get")

    def reset(self):
        self.host = self.get_option("host") or self._play_context.remote_addr

        # If we have a persistent ssh connection (ControlPersist), we can ask it to stop listening.
        cmd = self._build_command(
            self._play_context.ssh_executable, "-O", "stop", self.host
        )
        controlpersist, controlpath = self._persistence_controls(cmd)
        cp_arg = [a for a in cmd if a.startswith(b"ControlPath=")]

        # only run the reset if the ControlPath already exists or if it isn't
        # configured and ControlPersist is set
        run_reset = False
        if controlpersist and len(cp_arg) > 0:
            cp_path = cp_arg[0].split(b"=", 1)[-1]
            if os.path.exists(cp_path):
                run_reset = True
        elif controlpersist:
            run_reset = True

        if run_reset:
            display.vvv("sending stop: %s" % to_text(cmd))
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = p.communicate()
            status_code = p.wait()
            if status_code != 0:
                display.warning("Failed to reset connection:%s" % to_text(stderr))

        self.close()

    def close(self):
        self._connected = False
