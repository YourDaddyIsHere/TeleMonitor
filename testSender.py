from socket import *
s = socket(AF_INET,SOCK_DGRAM)  
HOST = '8.8.8.8'  
PORT = 65501
#s.bind((HOST,PORT))    
s.connect((HOST,PORT))
while True:
    #print "send!"
    port = 80
    port2 = 443
    command = "T debugger add dst port:%05d" % port
    command2 = "T debugger delete dst port:%05d" % port
    command3 = "T debugger add src port:%05d" % port2
    command4 = "T debugger delete src port:%05d" % port2
    #sh = "T debugger add:".encode("utf-8")
    sh = command.encode("utf-8")
    sh2 = command2.encode("utf-8")
    sh3 = command3.encode("utf-8")
    sh4 = command4.encode("utf-8")
    s.send(sh)
    s.send(sh2)
    s.send(sh3)
    s.send(sh4)
    break;