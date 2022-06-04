# Kubernetes Ingress 

Guard your Kubernetes ingress with Kanidm authentication and authorization.

## Prerequisites

The following are used in this example:

- [Kanidm](installing_the_server.html)
- [Kubernetes v1.23](https://docs.k0sproject.io/v1.23.6+k0s.2/install/)
- [Nginx Ingress](https://kubernetes.github.io/ingress-nginx/deploy/)
- [CertManager - With Cluster Issuer](https://cert-manager.io/docs/installation/)
- [ShellCheck](https://github.com/koalaman/shellcheck#user-content-installing)

You can setup your certificates manually instead of using CertManager if you are comfortable doign so. If it is your first time setting up CertManager, take your time with install and validation. For the `http01` solver the ingress port (8089) needs to be accessible from the internet.

## Instructions

1. Install the kubernetes dashboard

```shell
kubectl create -f https://raw.githubusercontent.com/kubernetes/kops/master/addons/kubernetes-dashboard/v1.10.1.yaml
```

2. Create a script from the content below, replacing every `<string>` (drop the `<>`) with appropriate values, then run it. This will example users, groups and the OAUTH2 configuration.

```shell
#!/bin/sh

# Analysis self for common errors.
shellcheck ./*.sh || exit 1

# Create User
kanidm account create k8s_example_user

# Create Group
kanidm group create k8s_example_group

# Attach User to Group
kanidm group add_member k8s_example_group k8s_example_user

# Setup Oauth Resource
displayname="The Example"
name=<oauth2_rs_name>
domain=<host>
kanidm login --name admin
kanidm system oauth2 create "$name" "$displayname" "$domain" --name admin
kanidm system oauth2 create_scope_map "$name" k8s_example_group openid email profile --name admin
kanidm system oauth2 get "$name" --name admin

## For <cookie_secret>
echo "Generating cookie secret:"
docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))));' 
```

3. Create a file called `k8s.kanidm-nginx-auth-example.yaml` with the block below, replacing every `<string>` (drop the `<>`) with appropriate values. 

```yaml
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: lets-encrypt-cluster-issuer
    nginx.ingress.kubernetes.io/auth-url: "https://$host/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://$host/oauth2/start?rd=$escaped_request_uri"
  name: external-auth-oauth2
  namespace: kube-system
spec:
  ingressClassName: nginx
  rules:
  - host: <hostname>
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubernetes-dashboard
            port:
              number: 80

---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: oauth2-proxy-kubernetes-dashboard
  name: oauth2-proxy-kubernetes-dashboard
  namespace: kube-system
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: oauth2-proxy-kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: oauth2-proxy
    spec:
      containers:
      - args:
        - --provider=kanidm
        - --email-domain=*
        - --upstream=file:///dev/null
        - --http-address=0.0.0.0:4180
        env:
        - name: OAUTH2_PROXY_CLIENT_ID
          value: <oauth2_rs_name>
        - name: OAUTH2_PROXY_CLIENT_SECRET
          value: <oauth2_rs_basic_secret>
        - name: OAUTH2_PROXY_COOKIE_SECRET
          value: <cookie_secret> # output b`cookie_secret` from docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))));'
        image: quay.io/oauth2-proxy/oauth2-proxy:latest
        imagePullPolicy: Always
        name: oauth2-proxy-kubernetes-dashboard
        ports:
        - containerPort: 4180
          protocol: TCP
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
---
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: oauth2-proxy-kubernetes-dashboard
  name: oauth2-proxy-kubernetes-dashboard
  namespace: kube-system
spec:
  ports:
  - name: http
    port: 4180
    protocol: TCP
    targetPort: 4180
  selector:
    k8s-app: oauth2-proxy-kubernetes-dashboard

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-proxy-kubernetes-dashboard
  namespace: kube-system
spec:
  ingressClassName: nginx
  rules:
  - host: <hostname>
    http:
      paths:
      - path: /oauth2
        pathType: Prefix
        backend:
          service:
            name: oauth2-proxy-kubernetes-dashboard
            port:
              number: 4180
  tls:
  - hosts:
    - <hostname>
    secretName: <hostname>-ingress-tls # replace . with - in the hostname
```

4. Apply the configuration by running the following command:

```shell
kubectl apply -f k8s.kanidm-nginx-auth-example.yaml
```

5. Check your deployment succeeded by running `kubctl -n kube-system get/describe/logs` 

Once it has finished deploying, you should be able to access it at `http://<hostname>`, which will prompt you for authentication.