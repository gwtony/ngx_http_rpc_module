Description
===========
Nginx rpc module: Set variable with value of rpc call response header

Usage
=====

* Nginx command
 - rpc_pass: rpc_pass /location key=header
	- /location: location to call
	- key: value of header with key

* Nginx variables
 - rpc_result: value of rpc call response header
  
* Example
```
   /location {
	   ...
	   rpc_pass /test key=my_header;
	   proxy_set_header new-header $rpc_result;
	   ...
   }
```
