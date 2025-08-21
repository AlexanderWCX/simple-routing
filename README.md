# simple-routing

Bash script implementing NAT routing for sharing WiFi internet connection with devices on Ethernet subnet

## Simple usage

```
sudo chmod +x ./simple-router.bash
sudo ./simple-router.bash start
```

## Save script to bin and make executable

```
sudo cp ./simple-router.bash /usr/local/bin/simple-router
sudo chmod +x /usr/local/bin/simple-router
```

## Enable NAT routing

```
sudo simple-router start
```

## Check if it's working

```
simple-router status
```

## Disable NAT routing

```
sudo simple-router stop
```
