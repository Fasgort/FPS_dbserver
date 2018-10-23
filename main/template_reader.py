import os, sys
import PIL
from PIL import Image
from time import sleep
import serial
ser = serial.Serial('COM3', 115200) # Establish the connection on a specific port
while True:
     buffer = ser.read(498);
     with open("D:\\Fasgort\\Desktop\\TFM\\FPS_dbserver\\main\\template.dat", 'wb') as output:
          output.write(buffer)

     ser.close();
     sys.exit()
