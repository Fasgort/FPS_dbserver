import os, sys, time
import PIL
from PIL import Image
from time import sleep
import serial
ser = serial.Serial('COM3', 115200) # Establish the connection on a specific port
while True:
     with open("D:\\Fasgort\\Desktop\\TFM\\FPS_dbserver\\main\\template.dat", 'rb') as output:
          buffer = output.read(498)
          for b in buffer:
               ser.write(b)
               time.sleep(0.1)
          output.close()

     ser.close();
     sys.exit()
