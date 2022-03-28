The Corelight software sensor is found by auto-discovery. The rbac.yaml
gives the VXLAN container permission to read k8s resources to facilitate
such discovery.

The software sensor is expected to have the following label:

metadata:
  labels:
    run: sensor

Build the VXLAN container, and simply add it to your existing pod definition
as illustrated in the deploy.yaml file.

