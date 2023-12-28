# How connect Ansible using GCP IAP

Example of how to use GCP IAP to connect to a VM using Ansible.

## Why

Ansible is a great tool to automate tasks on VMs. By default, Ansible uses SSH to connect to the VMs and execute the tasks. When VMs are isolated in a private network, like in a [GCP Virtual Private Cloud network](https://cloud.google.com/vpc/docs/vpc), it is not possible to connect to the VMs using SSH directly, and the connection must be routed through a VPN or a bastion host.

Alternatively, it is possible to use [GCP Identity-Aware Proxy (IAP)](https://cloud.google.com/iap/docs/using-tcp-forwarding) to connect to the VMs. There's no official support for Ansible to use IAP, but this project aims to provide an example with a specific [Ansible Connection Plugin](https://docs.ansible.com/ansible/latest/plugins/connection.html) to connect to the VMs using IAP.

## How it works

The [Ansible Connection Plugin](https://docs.ansible.com/ansible/latest/plugins/connection.html) is a Python script that Ansible executes to connect to the VMs. The script invokes the `gcloud compute [ssh|scp]` commands to connect to the VMs using IAP. In practice, the script will transparently replace the SSH connection.

![Connection to the VM via GCP IAP](./docs/diagram.drawio.svg)


Task example:

```yaml
---
- name: "[block] using 'gcp_ssh' connection plugin"
  connection: gcp_ssh
  block:
    - name: "Retrieve hostname"
      changed_when: false
      ansible.builtin.command:
        cmd: hostname
      register: hostname_output

    - name: "Debug hostname"
      ansible.builtin.debug:
        var: hostname_output.stdout
```

## How to use

Requirements:
- [Ansible CLI](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html)
- [Google Cloud CLI](https://cloud.google.com/sdk/docs/install)
- Ansible Collections
  ```bash
  # https://galaxy.ansible.com/google/cloud
  ansible-galaxy collection install google.cloud
  ```
- Google Cloud API access (described below)
  - Service Account with the correct permissions
- Enable the Ansible `gcp_ssh` connection plugin (described below)

### 1. On Google Cloud Platform, create the Service Account

Create an [IAM role](https://cloud.google.com/iam/docs/creating-custom-roles) with the following permissions:

1. Go to `IAM & Admin` > `Roles` > `Create Role`
    - Title: `ansible_iap_access`
    - Description: `Ansible IAP Access`
    - Role launch stage: `Alpha`
    - Assigned permissions:
      - `iap.tunnelInstances.accessViaIAP`
2. Click on `Create`

Create a [Service Account](https://cloud.google.com/iam/docs/service-accounts-create) with the following roles:

1. Go to `IAM & Admin` > `Service Accounts` > `Create Service Account`
    - Service account name: `ansible-iap-access`
    - Service account description: `Ansible IAP Access`
    - Click on `Done`
2. Bind the `Roles` to the `Service Account` (here called `Principal`)
  1. Go to `IAM & Admin` > `IAM`
  2. Click on `Grant Access` and fill the form:
      - Principal: the `Service Account` created on the previous step. Example: `ansible-iap-access@<MY_PROJECT>.iam.gserviceaccount.com`
      - Add the following roles:
        - `Compute Instance Admin (v1)`
        - `Compute Viewer`
        - `ansible_iap_access` (created on the previous step)
        - `IAP-secured Tunnel User`
  3. Click on `Save`
3. Download the `Service Account` JSON file:
  1. Open the new Service Account and go to the `Keys` tab
  2. Click on `Add Key` > `Create new key`
      - Key type: `JSON`
      - Click on `Create`
  3. Download the JSON file and save it on your computer. You will need it on the next steps.

### 2. Setup an Ansible project
1. Create the `ansible.cfg` file with the following content:
    ```ini
    [defaults]
    connection_plugins = ./plugins/connection
    pipelining = True
    ```
2. Copy the `gcp_ssh` connection plugin to the `plugins/connection` folder
3. Create the `inventory.gcp.yml` (it must end with `.gcp.yml`) with the following content:
    ```yaml
    ---
    plugin: google.cloud.gcp_compute
    projects:
      - <MY_PROJECT> # <-- change this
    filters:
      # Learn more about the filters, check the inventory plugin documentation:
      # https://docs.ansible.com/ansible/latest/collections/google/cloud/gcp_compute_inventory.html#parameter-filters
      # and Google's documentation:
      # https://cloud.google.com/compute/docs/reference/rest/v1/instances/aggregatedList
      - status = RUNNING
    auth_kind: serviceaccount
    scopes:
    - 'https://www.googleapis.com/auth/cloud-platform'
    - 'https://www.googleapis.com/auth/compute.readonly'
    keyed_groups:
      - prefix: aap
        key: application
    hostnames:
      - name
    compose:
      gcp_zone: zone
      gcp_region: networkInterfaces[0].subnetwork.region
      gcp_compute_ssh_flags: "--tunnel-through-iap --no-user-output-enabled --quiet"
      gcp_compute_scp_flags: "--tunnel-through-iap --quiet"
    ```
4. Create the `playbook.yml` with the following content:
    ```yaml
    ---
    - hosts: <MY_INSTANCES_GROUP>
      gather_facts: false
      connection: gcp_ssh
      tasks:
        - name: "Retrieve hostname"
          changed_when: false
          ansible.builtin.command:
            cmd: hostname
          register: hostname_output

        - name: "Debug hostname"
          ansible.builtin.debug:
            var: hostname_output.stdout

### 3. Test it

1. `gcloud` authentication:
    ```bash
    # Interactive authentication
    # https://cloud.google.com/sdk/gcloud/reference/auth/login
    gcloud auth login

    # OR using previously downloaded JSON file
    # https://cloud.google.com/sdk/gcloud/reference/auth/activate-service-account
    gcloud auth activate-service-account --key-file=<PATH_TO_JSON_FILE>
    ```
2. List the instances:
    ```bash
    ansible-inventory -i inventory.gcp.yml --graph
    ```
3. Run the playbook:
    ```bash
    ansible-playbook -i inventory.gcp.yml playbook.yml
    ```
