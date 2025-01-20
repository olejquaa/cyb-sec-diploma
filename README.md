# Дипломный проект TeachMeSkills Cybersecurity

---

## Contents

- [Заданиe](#задание)
- [Решение 1](#задание-1)
- [Решение 2](#задание-2)
- [Решение 3](#задание-3)
- [Решение 4](#задание-4)
- [Контакты](#контакты)

---

### Задание

#### 1. Расследование инцидентов

Изучить логи и примеры инцидентов, дать подробные ответы на данные вопросы: [soc_practical_test](/docs/SOC%20Practical.pdf)

#### 2. Создать скрипт на любом языке, который в информативном виде будет запускать скрипт с установкой:

AVML - создание дампа оперативной памяти
Volatility - фреймворк для работы с артефактами форензики
dwarf2json - создание symbol table для кастомного ядра linux
Сделать снимок Debug kernel для symbol table

#### 3. Автоматизировать процесс проверки url через virustotal

Напишите небольшой скрипт для автоматизированной проверки url. Можно использовать любой язык программирования

#### 4. Вы обнаружили уязвимость CVE-2021-41773 на вашем web сервере, Вам необходимо создать задачу для IT по её устранению

Что нужно будет сделать специалисту, чтобы исправить эту уязвимость? Напишите playbook для специалиста SOC L1

---

## Решения:

#### Задание 1

#### [Ответы на вопросы](/docs/Ответы%20на%20тест.pdf)

---

#### Задание 2

####

<details>
<summary style='font-size: 18px'><b>Скрипт по установке Volatility3</b></summary>

```sh
#!/bin/bash
#put this script in ~/Desktop and execute

progress() {
#progress bar code

local total=$1
local current=$2
local bar_length=40

local filled=$((current * bar_length / total ))
local empty_length=$((bar_length - filled))

local bar=$(printf "%${filled}s" | tr " " "#")
local empty=$(printf "%${empty_length}s" | tr " " "_")

clear
printf "\r[${bar}${empty}] %d%% | " "$((current * 100 / total))"
}


start() {
progress 1 0
printf "start install. Installing dependencies... \n"

sudo apt update && sudo apt full-upgrade -y   <----uncomment this if you need
sudo apt install python3-full -y
sudo apt install python3-pip

sleep 2
}


task1() {
printf "installing AVML. Making dump... \n"

wget https://github.com/microsoft/avml/releases/latest/download/avml
chmod ugo+x ./avml
sudo ./avml dump.lime

sleep 2
}


task2() {
printf "downloading debug kernel... \n"

echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.list
sudo apt install ubuntu-dbgsym-keyring
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622

#choose your dbgsym image
sudo apt install --yes linux-image-6.8.0-50-generic-dbgsym

sleep 2
}


task3() {
printf "installing Volatility... \n"

git clone https://github.com/volatilityfoundation/volatility3.git

sleep 2
}


task4() {
printf "installing dwarf2json... \n"

wget https://github.com/pathtofile/dwarf2json/releases/latest/download/dwarf2json-linux-amd64 -O dwarf2json
chmod +x dwarf2json

sleep 2
}


task5() {
printf "making Symbol Table... \n"

#check your kernel in /usr/lib/debug/boot/
sudo ./dwarf2json linux --system-map /boot/System.map-$(uname -r) --elf /usr/lib/debug/boot/vmlinux-6.8.0-50-generic > /home/user/Desktop/volatility3/volatility3/framework/symbols/linux/dbgkernel_ubuntu.json

sleep 2
}


task6() {
printf "starting Volatility... \n"

#you can choose your own directory, this one - by default
cd /home/user/Desktop/

sleep 2
}


total_tasks=7

for ((i = 1; i <= total_tasks; i++)); do
	case $i in
		1) start ;;
		2) task1 ;;
		3) task2 ;;
		4) task3 ;;
		5) task4 ;;
		6) task5 ;;
		7) task6 ;;

	esac


progress $total_tasks $i
done

echo -e "all done! Starting Volatility psaux"
sudo ./volatility3/vol.py -f /home/user/Desktop/dump.lime linux.psaux

```

[Ссылка на скрипт](/scripts/volatility5000.sh)

</details>

---

#### Задание 3

####

<details>
<summary style='font-size: 18px'><b>Скрипт по проверке URL на VirusTotal по API</b></summary>

```sh
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

```

[Ссылка на скрипт](/scripts/virustotal3000.sh)

</details>

---

#### Задание 4

#### [Playbook по устранению уязвимости CVE-2021-41773](/docs/Playbook%20для%20устранения%20уязвимости%20CVE-2021-41773.pdf)

---

### Контакты

Oleg Tihonenko - @olejquaa - ✉️ tihonenko.oleg@gmail.com
