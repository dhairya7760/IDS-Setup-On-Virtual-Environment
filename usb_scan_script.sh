#!/bin/bash



sudo apt-get update -y && \



sudo apt-get install clamav clamav-daemon -y && \



sudo apt-get install libjson-perl -y && \



sudo systemctl restart clamav-daemon  && \


# Create a new file called usb_scan.sh

touch usbscan.sh && \



# Add the code to the file using a heredoc

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



sudo chmod +x usbscan.sh && \



sudo ./usbscan.sh &

