# PyExchangePasswordSpray

Microsoft Exchange password spraying tool with proxy capabilities.


### Features
* Proxy List Support . HTTP & HTTPS
* Set a delay between each password spray.
* Use user & password list from a txt file
* Multi-threading support



### Usage

```
$ python3 exchange_password_spray.py -U userlist.txt -P password.txt --url https://webmail.example.org/EWS/Exchange.asmx --delay 62 -T 1 -ua "Microsoft Office/16.0 (Windows NT 10.0; MAPI 16.0.9001; Pro)" -O result.txt -v
```


```
##################### AUTH URLs samples #####################

# https://webmail.example.org/mapi/
# https://webmail.example.org/EWS/Exchange.asmx
# https://mail.example.org/autodiscover/autodiscover.xml
```

### Proxy Setups
Put your proxy list in ```proxy.txt``` file with the format ```IP:PORT```



# Screenshots
![Demo](MS_Exchange_password_spray.png?raw=true "Demo")




## Meta
Article link:
https://c99.sh/microsoft-exchange-password-spraying/

Moath Maharmeh -  moath@vegalayer.com

https://github.com/iomoath/PyExchangePasswordSpray