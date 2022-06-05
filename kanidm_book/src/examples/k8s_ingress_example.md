# Kubernetes Ingress

Guard your Kubernetes ingress with Kanidm authentication and authorization.


## Prerequisites

We recommend you have the following before continuing:

- [Kanidm](../installing_the_server.html) 
- [Kubernetes v1.23 or above](https://docs.k0sproject.io/v1.23.6+k0s.2/install/)
- [Nginx Ingress](https://kubernetes.github.io/ingress-nginx/deploy/)
- A fully qualified domain name with an A record pointing to your k8s ingress.
- [CertManager with a Cluster Issuer installed.](https://cert-manager.io/docs/installation/)


## Instructions

1. Create a Kanidm account and group:
   1.  Create a Kanidm account. Please see the section [Creating Accounts](../accounts_and_groups.md).
   1.  Give the account a password. Please see the section [Resetting Account Credentials](../accounts_and_groups.md).
   2.  Make the account a person. Please see the section [People Accounts](../accounts_and_groups.md).
   3.  Create a Kanidm group. Please see the section [Creating Accounts](../accounts_and_groups.md).
   4.  Add the account you created to the group you create. Please see the section [Creating Accounts](../accounts_and_groups.md).
2. Create a Kanidm OAuth2 resource:
   1. Create the OAuth2 resource for your domain. Please see the section [Create the Kanidm Configuration](../oauth2.md).
   2. Add a scope mapping from the resource you created to the group you create with the openid, profile, and email scopes. Please see the section [Create the Kanidm Configuration](../oauth2.md).
3. Create a `Cookie Secret` to for the placeholder `<COOKIE_SECRET>` in step 4:
      ```shell
      docker run -ti --rm python:3-alpine python -c 'import secrets,base64; print(base64.b64encode(base64.b64encode(secrets.token_bytes(16))).decode("utf-8"));'
      ```
4. Create a file called `k8s.kanidm-nginx-auth-example.yaml` with the block below. Replace every `<string>` (drop the `<>`) with appropriate values:
   1. `<FQDN>`: The fully qualified domain name with an A record pointing to your k8s ingress.
   2. `<KANIDM_FQDN>`: The fully qualified domain name of your Kanidm deployment.
   3. `<COOKIE_SECRET>`: The output from step 3.
   4. `<OAUTH2_RS_NAME>`: Please see the output from step 2.1 or [get](../oauth2.md) the OAuth2 resource you create from that step.
   5. `<OAUTH2_RS_BASIC_SECRET>`: Please see the output from step 2.1 or [get](../oauth2.md) the OAuth2 resource you create from that step.

    This will deploy the following to your cluster:
    - [modem7/docker-starwars](https://github.com/modem7/docker-starwars) - An example web site.
    - [OAuth2 Proxy](https://oauth2-proxy.github.io/oauth2-proxy/) - A OAuth2 proxy is used as an OAuth2 client with NGINX [Authentication Based on Subrequest Result]([Authentication Based on Subrequest Result](https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/)).

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
      name: website
      labels:
        app: website
    spec:
      revisionHistoryLimit: 1
      replicas: 1
      selector:
        matchLabels:
          app: website
      template:
        metadata:
          labels:
            app: website
        spec:
          containers:
            - name: website
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
      name: website
    spec:
      selector:
        app: website
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
      name: website
      namespace: kanidm-example
    spec:
      ingressClassName: nginx
      tls:
        - hosts:
            - <FQDN>
          secretName: <FQDN>-ingress-tls # replace . with - in the hostname
      rules:
      - host: <FQDN>
        http:
          paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: website
                port:
                  number: 8080

    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      labels:
        k8s-app: oauth2-proxy
      name: oauth2-proxy
      namespace: kanidm-example
    spec:
      replicas: 1
      selector:
        matchLabels:
          k8s-app: oauth2-proxy
      template:
        metadata:
          labels:
            k8s-app: oauth2-proxy
        spec:
          containers:
          - args:
            - --provider=oidc
            - --email-domain=*
            - --upstream=file:///dev/null
            - --http-address=0.0.0.0:4182
            - --oidc-issuer-url=https://<KANIDM_FQDN>/oauth2/openid/<OAUTH2_RS_NAME>
            - --code-challenge-method=S256
            env:
            - name: OAUTH2_PROXY_CLIENT_ID
              value: <OAUTH2_RS_NAME>
            - name: OAUTH2_PROXY_CLIENT_SECRET
              value: <OAUTH2_RS_BASIC_SECRET>
            - name: OAUTH2_PROXY_COOKIE_SECRET
              value: <COOKIE_SECRET>
            image: quay.io/oauth2-proxy/oauth2-proxy:latest
            imagePullPolicy: Always
            name: oauth2-proxy
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
        k8s-app: oauth2-proxy
      name: oauth2-proxy
      namespace: kanidm-example
    spec:
      ports:
      - name: http
        port: 4182
        protocol: TCP
        targetPort: 4182
      selector:
        k8s-app: oauth2-proxy

    ---
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: oauth2-proxy
      namespace: kanidm-example
    spec:
      ingressClassName: nginx
      rules:
      - host: <FQDN>
        http:
          paths:
          - path: /oauth2
            pathType: Prefix
            backend:
              service:
                name: oauth2-proxy
                port:
                  number: 4182
      tls:
      - hosts:
        - <FQDN>
        secretName: <FQDN>-ingress-tls # replace . with - in the hostname
    ```
5. Apply the configuration by running the following command:

    ```shell
    kubectl apply -f k8s.kanidm-nginx-auth-example.yaml
    ```
6. Check your deployment succeeded by running the following commands:
    ```shell
    kubectl -n kanidm-example get all
    kubectl -n kanidm-example get ingress
    kubectl -n kanidm-example get Certificate
    ```

    You may use kubectl's describe and log for troubleshooting. If there are ingress errors see the Ingress NGINX documentation's [troubleshooting page](https://kubernetes.github.io/ingress-nginx/troubleshooting/). If there are certificate errors see the CertManger documentation's [troubleshooting page](https://cert-manager.io/docs/faq/troubleshooting/).

    Once it has finished deploying, you will be able to access it at `https://<FQDN>` which will prompt you for authentication.


## Cleaning Up

1. Remove the resources create for this example from k8s:
    ```shell
    kubectl delete namespace kanidm-example
    ```

2. Remove the objects created for this example from Kanidm:
   1. Delete the account created in section Instructions step 1.
   2. Delete the group created in section Instructions step 2.
   3. Delete the OAuth2 resource created in section Instructions step 3.


## References

1. [NGINX Ingress Controller: External OAUTH Authentication](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)
2. [OAuth2 Proxy: OpenID Connect Provider](https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/oauth_provider#openid-connect-provider)
