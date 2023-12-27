run:
	ansible-playbook playbook-example.yml -vvv \
		-i ./inventory.gcp.yml

inventory-list:
	ansible-inventory -vvv \
		-i ./inventory.gcp.yml \
		--graph --vars
