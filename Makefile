run:
	ansible-playbook playbook.yml -vvv \
		-i ./inventory.gcp.yml

inventory-list:
	ansible-inventory -vvv \
		-i ./inventory.gcp.yml \
		--graph --vars --yaml --toml
