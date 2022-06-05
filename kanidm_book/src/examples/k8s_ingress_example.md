# Kubernetes Ingress 

Guard your Kubernetes ingress with Kanidm authentication and authorization.

## Prerequisites

The following are used in this example:

- [Kanidm](../installing_the_server.html)
- [Kubernetes v1.23 or above](https://docs.k0sproject.io/v1.23.6+k0s.2/install/)
- [Nginx Ingress](https://kubernetes.github.io/ingress-nginx/deploy/)
- [A Domain Name](https://domains.google/)
- [CertManager - With Cluster Issuer](https://cert-manager.io/docs/installation/)
- [ShellCheck](https://github.com/koalaman/shellcheck#user-content-installing)
- [modem7/docker-starwars](https://github.com/modem7/docker-starwars) - An example web site.

You can set up your certificates manually instead of using CertManager if you are comfortable doing so. If it is your first time setting up CertManager, take your time with installation and validation. For the `http01` solver the ingress port (8089) needs to be accessible from the internet - DNS validation is recommended.

## Instructions

1. Create a script `deploy.sh` from the content below, replacing every `<string>` (drop the `<>`) with appropriate values, then run it. This will create the user, group and OAUTH2 resource.

```shell
#!/bin/sh

# Analysis self for common errors.
shellcheck ./*.sh || exit 1

# Login
echo "User: idm_admin"
kanidm login --name idm_admin

# User Setup
kanidm account create k8s_example_user "K8s Example User" --name idm_admin
echo "Updating the credentials for k8s_example_user..."
kanidm account credential update k8s_example_user --name idm_admin
# > password
# > commit
kanidm account person extend k8s_example_user --legalname "John K8s Doe" --mail "jkd@email.address" --name idm_admin

# Create Group
kanidm group create k8s_example_group --name idm_admin

# Attach User to Group
kanidm group add_members k8s_example_group k8s_example_user --name idm_admin

# Setup Oauth Resource
displayname="The Example"
name=<oauth2_rs_name>
domain=<host>
echo "User: admin"
kanidm login --name admin
kanidm system oauth2 create "$name" "$displayname" "https://$domain" --name admin
kanidm system oauth2 create_scope_map "$name" k8s_example_group openid email profile --name admin
kanidm system oauth2 get "$name" --name admin

## For <cookie_secret>
echo "Generating cookie secret:"
docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))).decode("utf-8"));'
```

2. Create a file called `k8s.kanidm-nginx-auth-example.yaml` with the block below, replacing every `<string>` (drop the `<>`) with appropriate values.

```yaml
---
apiVersion: v1
kind: Namespace
metadata:
  name: kanidm-example
  labels:
    pod-security.kubernetes.io/enforce: restricted

---
apiVersion: apps/v1
kind: Deployment
metadata:
  namespace: kanidm-example
  name: my-homepage
  labels:
    app: my-homepage
spec:
  revisionHistoryLimit: 1
  replicas: 1
  selector:
    matchLabels:
      app: my-homepage
  template:
    metadata:
      labels:
        app: my-homepage
    spec:
      containers:
        - name: my-hompage
          image: modem7/docker-starwars
          imagePullPolicy: Always
          ports:
            - containerPort: 8080
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
  namespace: kanidm-example
  name: my-homepage
spec:
  selector:
    app: my-homepage
  ports:
    - protocol: TCP
      port: 8080
      targetPort: 8080

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/cluster-issuer: lets-encrypt-cluster-issuer
    nginx.ingress.kubernetes.io/auth-url: "https://$host/oauth2/auth"
    nginx.ingress.kubernetes.io/auth-signin: "https://$host/oauth2/start?rd=$escaped_request_uri"
  name: my-homepage
  namespace: kanidm-example
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - <hostname>
      secretName: <hostname>-ingress-tls # replace . with - in the hostname
  rules:
  - host: <hostname>
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-homepage
            port:
              number: 8080

---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    k8s-app: oauth2-proxy-kanidm-example
  name: oauth2-proxy-kanidm-example
  namespace: kanidm-example
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: oauth2-proxy-kanidm-example
  template:
    metadata:
      labels:
        k8s-app: oauth2-proxy-kanidm-example
    spec:
      containers:
      - args:
        - --provider=oidc
        - --email-domain=*
        - --upstream=file:///dev/null
        - --http-address=0.0.0.0:4182
        - --oidc-issuer-url=https://<kanidm-domain>/oauth2/openid/<oauth2_rs_name>
        - --code-challenge-method=S256
        env:
        - name: OAUTH2_PROXY_CLIENT_ID
          value: <oauth2_rs_name>
        - name: OAUTH2_PROXY_CLIENT_SECRET
          value: <oauth2_rs_basic_secret>
        - name: OAUTH2_PROXY_COOKIE_SECRET
          value: <cookie_secret> # output b`cookie_secret` from docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))));'
        image: quay.io/oauth2-proxy/oauth2-proxy:latest
        imagePullPolicy: Always
        name: oauth2-proxy-kanidm-example
        ports:
        - containerPort: 4182
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
    k8s-app: oauth2-proxy-kanidm-example
  name: oauth2-proxy-kanidm-example
  namespace: kanidm-example
spec:
  ports:
  - name: http
    port: 4182
    protocol: TCP
    targetPort: 4182
  selector:
    k8s-app: oauth2-proxy-kanidm-example

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: oauth2-proxy-kanidm-example
  namespace: kanidm-example
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
            name: oauth2-proxy-kanidm-example
            port:
              number: 4182
  tls:
  - hosts:
    - <hostname>
    secretName: <hostname>-ingress-tls # replace . with - in the hostname
```

3. Apply the configuration by running the following command:

```shell
kubectl apply -f k8s.kanidm-nginx-auth-example.yaml
```

4. Check your deployment succeeded by creating `check.sh` with the block below and running:
```shell
#!/bin/sh

# Analysis self for common errors.
shellcheck ./*.sh || exit 1

kubectl -n kanidm-example get all
kubectl -n kanidm-example get ingress
kubectl -n kanidm-example get Certificate

# kubctl -n kanidm-example describe and kubctl -n kanidm-example logs will do you well for troubleshooting.
# If there are ingress errors: https://kubernetes.github.io/ingress-nginx/troubleshooting/
# If there are certificate errors: https://cert-manager.io/docs/faq/troubleshooting/
```

Once it has finished deploying, you should be able to access it at `https://<hostname>`, which will prompt you for authentication.

## Cleaning Up

You know the drill.

```shell
kubectl delete namespace kanidm-example

# kanidm login --name idm_admin
kanidm account delete k8s_example_user --name idm_admin
kanidm group delete k8s_example_group --name idm_admin

# kanidm login --name admin
kanidm system oauth2 delete <oauth2_rs_name> --name admin
```

## References

- [NGINX Ingress Controller: External OAUTH Authentication](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)
- [OAuth2 Proxy: OpenID Connect Provider](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider#openid-connect-provider)
