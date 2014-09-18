## wireless driver library to help wrapping communication

Only ble is supported for the moment

###

The library use async reception for ble and need to format a umsg to send. Umsg is an abstract msg to send by the wireless.

Attribute of umsg depend of the request. The default attribute is 'dest_id'. Which is the serial id of the board. In the ble case, this serial is link to the mac address by the driver.
For the moment all that is static, in the future we will use advertising to discuss with the board on auto detect it. But not for the moment.

ubledriver.py:647
```py
_dest_available = {
    '#fake_serial' : uBleDest([ 0xea, 0x2a, 0xc2, 0x72, 0xed, 0x89 ])
}
```

### main.py

Ask information to the board

```sh
sudo python main.py
```

### update_firmware.py

Upload firmware

```sh
sudo python update_firmware.py <file_path>
```

### troubleshooting

The prog wait at the beginning -> reset the board (or wait) the prog will unfreeze

I receiver 'ERROR Disallowed command' -> your ble stack is freeze by unfinish connection. Restart it
   * `sudo hciconfig hci0 down up`

That crash -> report to me or create an issue :) wireshark is your best friend in waiting to have a complet an stable library.

/!\ Sudo can be avoid if you have an access to RAW_SOCKET with your user /!\
