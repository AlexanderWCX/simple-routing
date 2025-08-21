#!/bin/bash

# Simple Ubuntu NAT Router Script
# Enables packet forwarding and NAT between WiFi and Ethernet

# Configuration - Edit these to match your setup
WIFI_INTERFACE="wlan0"      # Your WiFi interface (internet connection)
ETH_INTERFACE="eth0"        # Your Ethernet interface (local network)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Function to detect network interfaces
detect_interfaces() {
    print_status "Using configured interfaces..."
    
    # Only auto-detect if using default/generic interface names
    if [[ "$WIFI_INTERFACE" =~ ^(wlan0|wifi)$ ]]; then
        print_status "Auto-detecting WiFi interface..."
        DETECTED_WIFI=$(ip link show | grep -E "wl|wlan" | head -1 | cut -d: -f2 | tr -d ' ')
        if [[ -n "$DETECTED_WIFI" ]]; then
            WIFI_INTERFACE="$DETECTED_WIFI"
            print_success "Detected WiFi interface: $WIFI_INTERFACE"
        fi
    else
        print_success "Using configured WiFi interface: $WIFI_INTERFACE"
    fi
    
    # Only auto-detect if using default/generic interface names
    if [[ "$ETH_INTERFACE" =~ ^(eth0|ethernet)$ ]]; then
        print_status "Auto-detecting Ethernet interface..."
        DETECTED_ETH=$(ip link show | grep -E "^[0-9]+: (eth[0-9]+|en[a-z0-9]+):" | grep -v "lo" | head -1 | cut -d: -f2 | tr -d ' ')
        if [[ -n "$DETECTED_ETH" ]]; then
            ETH_INTERFACE="$DETECTED_ETH"
            print_success "Detected Ethernet interface: $ETH_INTERFACE"
        fi
    else
        print_success "Using configured Ethernet interface: $ETH_INTERFACE"
    fi
    
    # Verify interfaces exist
    if ! ip link show "$WIFI_INTERFACE" &>/dev/null; then
        print_error "WiFi interface '$WIFI_INTERFACE' not found!"
        exit 1
    fi
    
    if ! ip link show "$ETH_INTERFACE" &>/dev/null; then
        print_error "Ethernet interface '$ETH_INTERFACE' not found!"
        exit 1
    fi
}

# Function to enable NAT routing
start_routing() {
    print_status "Enabling IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    print_success "IP forwarding enabled"
    
    print_status "Setting up NAT rules..."
    
    # Enable NAT (masquerading) - traffic from ethernet goes out via wifi
    iptables -t nat -A POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE
    
    # Allow forwarding from ethernet to wifi
    iptables -A FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT
    
    # Allow return traffic from wifi to ethernet (established connections)
    iptables -A FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
    
    print_success "NAT rules configured"
    print_success "Router started successfully!"
    echo
    print_status "Traffic from $ETH_INTERFACE will now be routed through $WIFI_INTERFACE"
    print_warning "Remember to configure static network settings on devices connected to $ETH_INTERFACE"
}

# Function to stop NAT routing
stop_routing() {
    print_status "Disabling IP forwarding..."
    echo 0 > /proc/sys/net/ipv4/ip_forward
    print_success "IP forwarding disabled"
    
    print_status "Clearing NAT rules..."
    
    # Remove our specific rules (safer than flushing everything)
    iptables -t nat -D POSTROUTING -o "$WIFI_INTERFACE" -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -i "$ETH_INTERFACE" -o "$WIFI_INTERFACE" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$WIFI_INTERFACE" -o "$ETH_INTERFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
    
    print_success "NAT rules cleared"
    print_success "Router stopped successfully!"
}

# Function to show current status
show_status() {
    print_status "Current NAT router status:"
    echo
    
    # Check IP forwarding
    FORWARDING=$(cat /proc/sys/net/ipv4/ip_forward)
    if [[ "$FORWARDING" == "1" ]]; then
        echo -e "IP Forwarding: ${GREEN}Enabled${NC}"
    else
        echo -e "IP Forwarding: ${RED}Disabled${NC}"
    fi
    
    # Check interfaces
    echo "Network Interfaces:"
    if ip link show "$WIFI_INTERFACE" &>/dev/null; then
        WIFI_IP=$(ip addr show "$WIFI_INTERFACE" | grep "inet " | awk '{print $2}' | head -1)
        echo "  $WIFI_INTERFACE (WiFi): ${WIFI_IP:-No IP assigned}"
    else
        echo -e "  $WIFI_INTERFACE (WiFi): ${RED}Not found${NC}"
    fi
    
    if ip link show "$ETH_INTERFACE" &>/dev/null; then
        ETH_IP=$(ip addr show "$ETH_INTERFACE" | grep "inet " | awk '{print $2}' | head -1)
        echo "  $ETH_INTERFACE (Ethernet): ${ETH_IP:-No IP assigned}"
    else
        echo -e "  $ETH_INTERFACE (Ethernet): ${RED}Not found${NC}"
    fi
    
    # Check NAT rules
    echo
    echo "NAT Rules:"
    if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE.*$WIFI_INTERFACE"; then
        echo -e "  MASQUERADE rule: ${GREEN}Active${NC}"
    else
        echo -e "  MASQUERADE rule: ${RED}Not found${NC}"
    fi
    
    if iptables -L FORWARD -n 2>/dev/null | grep -q "$ETH_INTERFACE.*$WIFI_INTERFACE"; then
        echo -e "  Forward rules: ${GREEN}Active${NC}"
    else
        echo -e "  Forward rules: ${RED}Not found${NC}"
    fi
}

# Function to test basic connectivity
test_routing() {
    print_status "Testing routing setup..."
    
    # Check if WiFi has internet
    if ping -c 2 -W 3 8.8.8.8 >/dev/null 2>&1; then
        print_success "Internet connectivity via $WIFI_INTERFACE: OK"
    else
        print_error "No internet connectivity via $WIFI_INTERFACE"
        return 1
    fi
    
    # Check IP forwarding
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == "1" ]]; then
        print_success "IP forwarding: Enabled"
    else
        print_error "IP forwarding: Disabled"
        return 1
    fi
    
    # Check NAT rules
    if iptables -t nat -L -n | grep -q "MASQUERADE.*$WIFI_INTERFACE"; then
        print_success "NAT rules: Configured"
    else
        print_error "NAT rules: Missing"
        return 1
    fi
    
    print_success "Basic routing tests passed"
    echo
    print_warning "To complete setup, configure devices on $ETH_INTERFACE with:"
    print_warning "  - Static IP in same subnet as this machine's $ETH_INTERFACE"
    print_warning "  - Gateway pointing to this machine's $ETH_INTERFACE IP"
    print_warning "  - DNS servers (e.g., 8.8.8.8, 8.8.4.4)"
}

# Main script logic
case "$1" in
    start)
        check_root
        detect_interfaces
        start_routing
        ;;
    stop)
        check_root
        detect_interfaces
        stop_routing
        ;;
    restart)
        check_root
        detect_interfaces
        stop_routing
        sleep 1
        start_routing
        ;;
    status)
        detect_interfaces
        show_status
        ;;
    test)
        detect_interfaces
        test_routing
        ;;
    *)
        echo "Simple Ubuntu NAT Router Script"
        echo "Usage: $0 {start|stop|restart|status|test}"
        echo
        echo "Commands:"
        echo "  start   - Enable NAT routing (WiFi to Ethernet)"
        echo "  stop    - Disable NAT routing and cleanup"
        echo "  restart - Stop and start NAT routing"
        echo "  status  - Show current routing status"
        echo "  test    - Test routing configuration"
        echo
        echo "This script only handles packet forwarding and NAT."
        echo "You need to manually configure IP addresses on connected devices."
        echo
        echo "Examples:"
        echo "  sudo $0 start     # Start NAT routing"
        echo "  sudo $0 stop      # Stop NAT routing" 
        echo "  $0 status         # Check status"
        exit 1
        ;;
esac