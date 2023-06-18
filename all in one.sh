#!/bin/bash

sudo add-apt-repository ppa:oisf/suricata-stable -y && \

sudo apt-get update && \

sudo apt-get install suricata -y && \

sudo systemctl enable suricata.service && \

sudo systemctl status suricata.service && \

sudo systemctl stop suricata.service && \

sudo touch /etc/suricata/rules/local.rules && \

# Appending network rules to local rules file

sudo echo 'alert tcp any any -> any any (msg:"SYN scan detected"; flags:S; threshold: type both, track by_src, count 20, seconds 5; sid:1000001; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"FIN scan detected"; flags:F; sid:1000002; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert udp any any -> any any (msg:"UDP scan detected"; threshold: type both, track by_src, count 10, seconds 5; sid:1000003; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Xmas scan detected"; flags:FPU; sid:1000004; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Null scan detected"; flags:0; sid:1000005; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"TCP Connect scan detected"; flags:S; threshold: type both, track by_src, count 20, seconds 1; sid:1000006; rev:2;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert tcp any any -> any any (msg:"Version Scan detected"; threshold: type both, track by_src, count 20, seconds 5; sid:1000007; rev:1;)' >> /etc/suricata/rules/local.rules  && \

sudo echo 'alert icmp any any -> any any (msg:"ICMP Ping Detected"; sid:1000008; rev:1;)' >> /etc/suricata/rules/local.rules  && \

# Appending Web rules to local rules file

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

# Modifying suricata configuration file

sudo sed -i '18s/.*/    HOME_NET: "[192.168.0.0\/24]"/' /etc/suricata/suricata.yaml && \

sudo sed -i '589s/.*/  - interface: enp0s3/' /etc/suricata/suricata.yaml && \

sudo sed -i '669s/.*/  - interface: enp0s3/' /etc/suricata/suricata.yaml && \

sudo sed -i '132s/.*/      community-id: true/' /etc/suricata/suricata.yaml && \

sudo sed -i '1925i \  - /etc/suricata/rules/local.rules' /etc/suricata/suricata.yaml && \

sudo suricata-update && \

sudo suricata -T -c /etc/suricata/suricata.yaml -v && \

sudo systemctl start suricata.service  && \

sudo systemctl status suricata.service && \

sudo apt-get install clamav clamav-daemon -y && \

sudo apt-get install libjson-perl -y && \

sudo systemctl restart clamav-daemon  && \

# Creating a new file called usbscan.sh

touch usbscan.sh && \

# Appending a code into the file for usb scan

cat << 'EOF' > usbscan.sh

#!/bin/bash



usb_scanned=false



while true



do



    if [ "$usb_scanned" = false ] && [ "$(ls -A /media/dhairya)" ]; then



        USB_NAME=$(ls /media/dhairya/)



        clamscan -r --infected --no-summary /media/dhairya/$USB_NAME | awk -v usbname="$USB_NAME" -F": " '/FOUND/{print "{\"malware\":\""$2"\",\"file\":\"" file $1 "\",\"status\":\"Malicious File Detected !\",\"timestamp\":\"" strftime("%Y-%m-%d %H:%M:%S") "\",\"usb\":\"" usbname "\"}"}' >> /home/dhairya/Downloads/output.json



        usb_scanned=true



    fi



    sleep 3 # wait for 3 seconds before checking again



done

EOF

#Giving execute permission to the created file
sudo chmod +x usbscan.sh && \

#Making the file to be run in the background

sudo ./usbscan.sh &