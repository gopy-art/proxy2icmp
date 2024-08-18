#!/bin/bash

chmod +x cmd/proxy2icmp/proxy2icmp

if [ "$1" = "client" ]; then
    echo "starting setup client side..."

    DIRECTORY="/usr/share/p2iClient"
    if [ -d "$DIRECTORY" ]; then
        echo "$DIRECTORY does exist."
    else
        mkdir -p "$DIRECTORY"
        echo "Directory created successfully."

    fi
    chmod 755 p2iClient.service
    cp cmd/proxy2icmp/proxy2icmp $DIRECTORY
    cp p2iClient.service /etc/systemd/system

    file_path="/etc/systemd/system/p2iClient.service"
    old_string0="listenIp"
    new_string0=$2
    old_string1="serverIp"
    new_string1=$3
    old_string2="port"
    new_string2=$4
    old_string3="protocol"
    new_string3=$5

    # Replace the string in the file
    if [ "$5" = "socks5" ]; then
        sed -i "s/-t $old_string1:$old_string2 $old_string3/-$new_string3 1/g" "$file_path"
    elif [ "$5" = "tcp" ]; then
        sed -i "s/$old_string3/-$new_string3 1/g" "$file_path"
    elif [ "$5" = "udp" ]; then
        sed -i "s/$old_string3//g" "$file_path"
    else
        exit
    fi
    sed -i "s/$old_string0/$new_string0/g" "$file_path"
    sed -i "s/$old_string1/$new_string1/g" "$file_path"
    sed -i "s/$old_string2/$new_string2/g" "$file_path"
    echo "set args completed."

    # systemctl daemon-reload
    # systemctl start p2iClient.service
    # systemctl enable p2iClient.service
    # echo "finished setup."
    # echo "enjoy."

else
    if [ "$1" = "server" ]; then
        echo "starting setup server side..."
        DIRECTORY="/usr/share/p2iServer"
        if [ -d "$DIRECTORY" ]; then
            echo "$DIRECTORY does exist."
        else
            mkdir -p "$DIRECTORY"
            echo "Directory created successfully."

        fi
        chmod 755 p2iServer.service
        cp cmd/proxy2icmp/proxy2icmp $DIRECTORY
        cp p2iServer.service /etc/systemd/system
        systemctl daemon-reload
        systemctl start p2iServer.service
        systemctl enable p2iServer.service
        echo "finished setup."
        echo "enjoy."
    fi
fi
