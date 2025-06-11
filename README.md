# Nginx configuration

```
    sudo mkdir -p /var/www/html/dashboard
    sudo cp -r /home/vh/Desktop/Dashboard/FrontEnd/page/* /var/www/html/dashboard/
```


# SSL - HTTP/2.0

1. Nếu đã có sẵn 1 public domain

    apt-get update  
    sudo apt-get install certbot  
    apt-get install python3-certbot-nginx 

2. Nếu chưa có domain, thực hiện tự kí

    a. Cài đặt  
    *`Mã hóa chuẩn ed25519`*
    ```
    - sudo mkdir /etc/ssl/private  
    - sudo chmod 700 /etc/ssl/private  
    - Tạo private key: openssl genpkey -algorithm ED25519 -out /etc/ssl/private/nginx-ed25519.key
    - Tạo file SAN trong /etc/ssl: 
    > [req]
            distinguished_name = req_distinguished_name
            x509_extensions = v3_req
            prompt = no

            [req_distinguished_name]
            CN = localhost

            [v3_req]
            subjectAltName = @alt_names

            [alt_names]
            DNS.1 = localhost
            IP.1 = 192.168.5.141 
    - Tạo CSR với SAN và key: openssl req -new -key /etc/ssl/private/nginx-ed25519.key -out /etc/ssl/certs/nginx-ed25519.csr -config /etc/ssl/openssl-ed25519.cnf 
    - Tạo cert từ key và CSR: openssl x509 -req -in /etc/ssl/certs/nginx-ed25519.csr -signkey /etc/ssl/private/nginx-ed25519.key -out /etc/ssl/certs/nginx-ed25519.crt -days 365 -extensions v3_req -extfile /etc/ssl/openssl-ed25519.cnf 
    sudo nano /etc/nginx/conf.d/ssl.conf
    ``` 
    *`Mã hóa chuẩn rsa`*
    ```
        ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
        ssl_dhparam /etc/ssl/certs/dhparam.pem;
    ```
    
    b. File cấu hình `ssl.conf`

    ```
    server {
        listen 443 http2 ssl;
        listen [::]:443 http2 ssl;
        server_name localhost;
        
        ssl_certificate /etc/ssl/certs/nginx-ed25519.crt;
        ssl_certificate_key /etc/ssl/private/nginx-ed25519.key;

        root /var/www/html/dashboard;
        index login-page.html;

        # Phục vụ file tĩnh
        location / {
            try_files $uri $uri/ =404;
        }

        # Proxy API sang Flask backend
        location /api/ {
            proxy_pass http://127.0.0.1:8110/api/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
    ``` 

    c. File cấu hình `default`
    ```
    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        server_name localhost;

        return 301 https://$host$request_uri;
    }
    ```

    d. Check 
    sudo nginx -t
    sudo systemctl reload nginx
    curl -I --http2 -k https://localhost