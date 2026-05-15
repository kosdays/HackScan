#!/bin/bash

#Autor: Kosdays
#Inspirado por: S4vitar & Security Community

# Colores
export green="\e[0;32m"
export red="\e[0;31m"
export yellow="\e[0;33m"
export blue="\e[0;34m"
export cyan="\e[0;36m"
export reset="\e[0m"

#Comprobación de privilegios (root)
if [ "$(id -u)" -ne 0 ]; then
    echo -e "\n${red}[!] Este script debe ejecutarse como root (sudo).${reset}\n"
    exit 1
fi

# Creamos una carpeta para guardar logs
export folder_name="logs"

# Función de salida controlada
trap ctrl_c INT
function ctrl_c(){
    echo -e "\n\n${red}[!] Operación abortada por el usuario${reset}\n"
    tput cnorm; exit 1
}


# 1. Capa de Identificación de OS (TTL Analysis)
function get_os_logic(){
    local ttl=$1
    if [[ "$ttl" =~ ^[0-9]+$ ]]; then
        if [ "$ttl" -le 64 ]; then echo "Linux";
        elif [ "$ttl" -le 128 ]; then echo "Windows";
        else echo "Desconocido"; fi
    else echo "Inalcanzable"; fi
}

# 2. EternalBlue PoC (Auditoría Condicional)
function audit_stage(){
    local ip=$1
    local ports=$2

    if echo "$ports" | grep -q "445"; then
        echo -ne "\n${yellow}[?] Se detectó SMB (445). ¿Auditar MS17-010? (s/n): ${reset}"
        read -r response
        if [[ "$response" =~ ^[Ss]$ ]]; then
            echo -e "${red}[!] Iniciando auditoría de EternalBlue...${reset}"
            nmap --script smb-vuln-ms17-010 -p445 "$ip" -oN .target_vuln > /dev/null 2>&1
            if grep -q "VULNERABLE" .target_vuln; then
                echo -e "${red}[CRÍTICO] El host es VULNERABLE a MS17-010${reset}"
                cat .target_vuln | grep -A 5 "VULNERABLE"
            else
                echo -e "${green}[+] El host no parece vulnerable.${reset}"
            fi
            rm .target_vuln
        fi
    fi
}

# 3. Capa de Escaneo de Puertos
function smart_nmap(){
    local ip=$1
    echo -e "${yellow}[*] Iniciando descubrimiento táctico...${reset}"
    
    local ports=$(sudo nmap -p- --open -sS --min-rate 5000 -n -Pn "$ip" | grep -oP '\d+(?=/tcp)' | xargs | tr ' ' ',')
    
    if [ ! -z "$ports" ]; then
        echo -e "${green}[+] Puertos detectados: ${cyan}$ports${reset}"
        nmap -sCV -p"$ports" "$ip" -oN .tmp_scan > /dev/null 2>&1
        
        echo -e "${blue}================ RESULTADOS PARA $ip ================${reset}"
        cat .tmp_scan | awk '/PORT/,/MAC/'
        echo -e "${blue}======================================================${reset}"
        
        audit_stage "$ip" "$ports"
        rm .tmp_scan
    else
        echo -e "${red}[!] No se detectaron servicios TCP abiertos.${reset}"
    fi
}

# 4. Función Principal (Orquestador)
function main(){
    tput civis
    local target=$1
    
    if [ ! -d "$folder_name" ]; then
        mkdir "$folder_name"
    fi

    local log_file="${folder_name}/scan_${target}.log"
    
    {
        echo -e "\n${cyan}---[ H4CKSCAN - Pentesting Tool ]---${reset}"
        echo -e "[*] Sesión iniciada: $(date)"
        
        local ping_data=$(ping -c 1 -W 2 "$target" 2>/dev/null)
        local ttl_val=$(echo "$ping_data" | grep -oP 'ttl=\K\d+' | head -n 1)
        
        if [ ! -z "$ttl_val" ]; then
            local os_guessed=$(get_os_logic "$ttl_val")
            echo -e "${green}[+] Objetivo vivo (TTL: $ttl_val -> $os_guessed)${reset}"
        else
            echo -e "${red}[!] No hay respuesta ICMP. Escaneo ciego...${reset}"
        fi
        
        smart_nmap "$target"
        echo -e "\n[*] Sesión finalizada: $(date)"
        
    } | tee "$log_file"

    echo -e "\n${yellow}[*] Reporte consolidado en: ${cyan}${log_file}${reset}"
    tput cnorm
}

if [ "$1" ]; then
    main "$1"
else
    echo -e "\n${red}[!] Uso: $0 <IP_TARGET>${reset}\n"
fi
