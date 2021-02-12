# OpenShift Collection for Ansible


## Installation and Usage

### Installing the Collection from Automation Hub

Before using the OpenShift collection, you need to install it with the Automation Hub CLI:

    ansible-galaxy collection install redhat.openshift

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: redhat.openshift
    version: 1.0.1
```

### Installing the OpenShift Python Library

Content in this collection requires the [OpenShift Python client](https://pypi.org/project/openshift/) to interact with Kubernetes' APIs. You can install it with:

    pip3 install openshift

### Using modules from the OpenShift Collection in your playbooks

It's preferable to use content in this collection using their Fully Qualified Collection Namespace (FQCN), for example `redhat.openshift.openshift`:

```yaml
---
plugin: redhat.openshift.openshift
connections:
  - namespaces:
    - testing
```

For documentation on how to use individual plugins included in this collection, please see the links in the 'Included content' section earlier in this README.


## More Information

For more information about Ansible's Kubernetes and OpenShift integrations, join the `#ansible-kubernetes` channel on Freenode IRC, and browse the resources in the [Kubernetes Working Group](https://github.com/ansible/community/wiki/Kubernetes) Community wiki page.

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.
