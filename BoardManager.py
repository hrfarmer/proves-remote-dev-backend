import threading
import time

import serial
import serial.tools.list_ports


class BoardManager:
    def __init__(self):
        self.vid = 0x1209  # PROVES Kit VID
        self.pids = [
            0xE004,  # PROVES Kit v4 PID
            0x0011,  # PROVES Kit Testing PID
        ]
        self.port = None
        self.serial = None
        self.is_connected = False
        self.monitor_thread = None
        self.read_thread = None
        self.data_callback = None
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitor_connection, daemon=True)
        self.monitor_thread.start()

    def set_data_callback(self, callback):
        """Set a callback function to be called when data is received.
        
        Args:
            callback: A function that takes a single argument (the received data).
                     The callback will be called in a separate thread whenever data
                     is received from the board.
        """
        self.data_callback = callback

    def _monitor_connection(self):
        """Continuously monitor for board availability and maintain connection.
        
        This method runs in a separate thread and checks every second if the board
        is connected. If disconnected, it attempts to reconnect automatically.
        """
        while True:
            if not self.is_connected:
                try:
                    self.connect()
                except Exception:
                    pass  
            time.sleep(1) 

    def _read_data(self):
        """Continuously read data from the serial port and call the callback if set.
        
        This method runs in a separate thread and continuously checks for available
        data on the serial port. When data is received, it calls the registered
        callback function with the received data.
        """
        while self.is_connected:
            try:
                if self.serial and self.serial.is_open:
                    if self.serial.in_waiting:
                        data = self.serial.read(self.serial.in_waiting)
                        if self.data_callback:
                            self.data_callback(data)
            except Exception:
                self.is_connected = False
                break
            time.sleep(0.01)  # Small delay to prevent CPU overuse
    
    def send_data(self, data):
        """Send data to the board.
        
        Args:
            data: The data to send to the board.
        """
        self.serial.write(data)

    def connect(self):
        """Establish connection with a PROVES Kit board.
        
        Searches for a board with matching VID and PID, then establishes a serial
        connection. If successful, starts a thread to handle data reception.
        
        Returns:
            bool: True if connection is successful.
            
        Raises:
            Exception: If no matching device is found or if connection fails.
        """
        if self.is_connected:
            return True

        all_ports = serial.tools.list_ports.comports()
        
        for port in all_ports:
            if port.vid == self.vid and port.pid in self.pids:
                self.port = port.device
                break
        
        if not self.port:
            raise Exception(f"No device found with VID={hex(self.vid)} and PIDs={[hex(pid) for pid in self.pids]}")
        
        try:
            self.serial = serial.Serial(
                port=self.port,
                baudrate=9600,
                timeout=1
            )
            self.is_connected = True
            
            # Start the data reading thread
            self.read_thread = threading.Thread(target=self._read_data, daemon=True)
            self.read_thread.start()
            
            return True
        except serial.SerialException as e:
            self.is_connected = False
            raise Exception(f"Failed to connect to {self.port}: {str(e)}")

    def disconnect(self):
        """Disconnect from the currently connected board.
        
        Closes the serial connection and resets all connection-related attributes.
        This method is called automatically when the object is destroyed.
        """
        if self.serial and self.serial.is_open:
            self.serial.close()
        self.serial = None
        self.port = None
        self.is_connected = False

    def __del__(self):
        self.disconnect()
