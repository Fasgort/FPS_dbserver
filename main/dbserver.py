import os, sys
import PIL
from PIL import Image
from time import sleep
import serial
ser = serial.Serial('COM3', 115200) # Establish the connection on a specific port
while True:
     #im1 = PIL.Image.frombytes("L",(160,120),ser.read(19200))
     #im1.save("D:\\Fasgort\\Desktop\\TFM\\FPS_dbserver\\main\\fingerprint_test.bmp")
     #ser.read(2);
     
     im2 = PIL.Image.frombytes("L",(232,139),ser.read(32248))
     #im2 = PIL.Image.frombytes("L",(232,224),ser.read(52116))
     im2.save("D:\\Fasgort\\Desktop\\TFM\\FPS_dbserver\\main\\fingerprint_test2.bmp")
     ser.read(2);

     ser.close();
     sys.exit()
