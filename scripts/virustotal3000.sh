#!/bin/bash

#installing dialog
check_and_install() {
    PACKAGE=$1
    if dpkg -l | grep -q "^ii  $PACKAGE "; then
        echo "$PACKAGE installed."
    else
        echo "Installing $PACKAGE"
        sudo apt install -y $PACKAGE
    fi
}


echo "Checking dependencies... curl; dialog; jq"
check_and_install "curl"
check_and_install "dialog"
check_and_install "jq"



#seting API key
API_KEY="6388477916de5bb5048ae16a86b42597de7a420af9feb6d45a308c5c8b89fc5c"

#start exec
dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Starting execution..." 10 60
sleep 3


# url validation
validate_url() {
    local LOCAL_URL="$1"
    # Regular expression for validating URL (http and https)
    if [[ $LOCAL_URL =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(:[0-9]+)?(/.*)?$ ]]; then
        return 0  # URL is valid
    else
        return 1  # URL is invalid
    fi
}


check_url_exists() {
    local LOCAL_URL="$1"
    if curl --output /dev/null --silent --head --fail "$LOCAL_URL"; then
        return 0  # URL exists
    else
        return 1  # URL does not exist
    fi
}

while true; do
    tempfile=$(mktemp)

    #user input URL
    URL=$(dialog --title "| VirusTotal URL autochecker 3000 |" --inputbox "Paste URL for check !!!!" 10 60 "http://" 3>&1 1>&2 2>"$tempfile")

    # Check cancel
    if [ $? -ne 0 ]; then
        dialog --title "| VirusTotal URL autochecker 3000 |" --msgbox "YOU PRESS CANCEL!! NOOOOOOOO!!!!" 10 60
        rm "$tempfile"
	clear
	exit 1
	
    fi

   #setting input variable
    input=$(<"$tempfile")
    rm "$tempfile"

    #cheking input is empty
    if [ -z "$input" ]; then
        dialog --title "| VirusTotal URL autochecker 3000 |" --msgbox  "Nothing to analyse. Set correct URL" 10 60
        continue  
    fi

    #validating URL
    if validate_url "$input"; then
        if check_url_exists "$input"; then
            URL="$input"  # Assign valid input to URL variable
            break  # Exit the loop if valid and reachable URL is provided
        else
            dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "URL unreachable: $input. Set correct URL " 10 60
            sleep 2
        fi
    else
        dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Incorrect URL: $input" 10 60
        sleep 2
    fi
done


#send request
dialog  --title "| VirusTotal URL autochecker 3000 |" --infobox "Checking $URL! \nSending request..." 10 60 & 3>&1 1>&2 2>&3
sleep 5


RESPONSE=$(curl -s --request POST --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: $API_KEY" --form "url=$URL")

dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Checking $URL! \nChecking response..." 10 60 & 3>&1 1>&2 2>&3
sleep 3


ANALYSIS_URL=$(echo "$RESPONSE" | jq -r '.data.links.self')
ANALYSIS_ID=$(echo "$RESPONSE" | jq -r '.data.id')

dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Checking $URL! \nSending analysis request..." 10 60 & 3>&1 1>&2 2>&3
sleep 3


#REPORT_MSG=""
REPORT_STATUS=""


#checking analysis
check_analysis_status() {
    local ID=$1
    local REPORT

    while true; do
        REPORT=$(curl -s --request GET --url "https://www.virustotal.com/api/v3/analyses/$ID" --header "x-apikey: $API_KEY")
        
        STATUS=$(echo "$REPORT" | jq -r '.data.attributes.status')

        dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Analysis request status: $STATUS" 10 60 3>&1 1>&2 2>&3
        sleep 2


        if  [ "$STATUS" = "completed" ]; then
            
            #REPORT_MSG=$(echo $REPORT | jq -r '.data.attributes.stats')

            MALICIOUS=$(echo $REPORT | jq -r '.data.attributes.stats.malicious')
            SUSPICIOUS=$(echo $REPORT | jq -r '.data.attributes.stats.suspicious')
            UNDETECTED=$(echo $REPORT | jq -r '.data.attributes.stats.undetected')
            HARMLESS=$(echo $REPORT | jq -r '.data.attributes.stats.harmless')
            TIMEOUT=$(echo $REPORT | jq -r '.data.attributes.stats.timeout')
            
            dialog --title "| VirusTotal URL autochecker 3000 |" --msgbox "REPORT: \n
            Malicious: $MALICIOUS\n
            Suspicious: $SUSPICIOUS\n
            Undetected: $UNDETECTED\n
            Harmless: $HARMLESS" 10 60 3>&1 1>&2 2>&3

            break
        else
          dialog --title "| VirusTotal URL autochecker 3000 |" --infobox "Waiting for report" 10 60 3>&1 1>&2 2>&3
            sleep 10
        fi
    done
}

check_analysis_status "$ANALYSIS_ID"



#quit
dialog  --title "| VirusTotal URL autochecker 3000 |" --infobox "Quiting..." 10 60
sleep 1
clear
