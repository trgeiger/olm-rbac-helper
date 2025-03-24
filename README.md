#Proof of Concept OLM RBAC Helper Plugin

This plugin takes in a manifest file for a ClusterExtension and checks the installer ServiceAccount specified in that manifest file for all the permissions it requires to install and manage the ClusterExtension. If any are missing, it outputs the missing RBAC in the form of a complete Role and/or ClusterRole manifest.

Build the binary with a "kubectl" prefix and place somewhere in your `$PATH`:
```sh
go build -o ~/.local/bin/kubectl-olmrbac .
```

The plugin has 2 required arguments, an extension manifest file and a catalog server URL, i.e.:
```sh
kubectl olmrbac argocd.yaml localhost:8080
```

You can expose the catalog server from a running cluster by port-forwarding its service:
```sh
kubectl -n olmv1-system port-forward svc/catalogd-service 8080:443
```

By default, the plugin will simply print the missing RBAC to standard output. You can save the output to a file by using the `--output/-o` flag.

If you run the plugin against a ServiceAccount that has no existing permissions, it *should* give you a resulting Role and ClusterRole that encompass all the required RBAC for installing and managing that ClusterExtension.
