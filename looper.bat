@echo on 
:loop 
ping 127.0.0.1 -n 1 -4 & goto=:loop