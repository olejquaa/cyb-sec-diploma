#!/bin/bash
#lines=$(tput lines)
#echo $lines

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

sudo apt update #&& sudo apt full-upgrade -y   <----uncomment this if you need
#sudo apt install python3-full -y
#sudo apt install python3-pip

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

cd /home/user/Desktop/

#sudo ./volatility3/vol.py -f /home/user/Desktop/dump.lime linux.psaux
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

