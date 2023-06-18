#!/bin/bash



sudo systemctl stop suricata.service && \



sudo echo 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Illegitimate Download page Detected"; uricontent:"/download.php"; classtype:web-application-activity; sid:1000009; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Illegitimate Login page Detected"; uricontent:"/login.php"; classtype:web-application-activity; sid:1000010; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Illegitimate Signup page Detected"; uricontent:"/register.php"; classtype:web-application-activity; sid:1000011; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Illegitimate Signup page Detected"; uricontent:"/signup.php"; classtype:web-application-activity; sid:1000012; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Illegitimate Upload page Detected"; uricontent:"/upload.php"; classtype:web-application-activity; sid:1000013; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo '#Rule for detecting HTTP requests to suspicious IP addresses' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http any any -> any any (msg:"Suspicious IP address Detected"; pcre:"/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/"; content:"/"; threshold:type limit, track by_src, seconds 3600, count 1; sid:1000014; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo '#Rule for detecting HTTP requests to suspicious Top level domains' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http any any -> any any (msg:"Suspicious TLD Detected"; pcre:"/\.(tk|ml|ga|cf|gq)$/i"; content:"/"; sid:1000015; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo '#Rule for detecting HTTP requests to domains with suspicious character encoding' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http any any -> any any (msg:"HTTP request to domain with suspicious character encoding detected"; pcre:"/^xn--|^[\x80-\xFF]/"; content:"/"; sid:1000016; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo echo '#Rule for detecting HTTP requests to domains with suspicious subdomains' >> /etc/suricata/rules/local.rules  && \



sudo echo 'alert http any any -> any any (msg:"HTTP request to domain with suspicious subdomain"; pcre:"/^.*\.(?:gdn|bid|ooo|win|date|wang|loan|men|click|top)$/i"; content:"/"; sid:1000017; rev:1;)' >> /etc/suricata/rules/local.rules  && \



sudo suricata-update && \



sudo suricata -T -c /etc/suricata/suricata.yaml -v && \



sudo systemctl start suricata.service && \



sudo systemctl status suricata.service

