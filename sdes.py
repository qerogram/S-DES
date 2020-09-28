# Author : qerogram

class sdes() :
    P4      = [2, 4, 3, 1]
    P8      = [6, 3, 7, 4, 8, 5, 10, 9]
    P10     = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    EP      = [4, 1, 2, 3, 2, 3, 4, 1]
    IP      = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_1    = [4, 1, 3, 5, 7, 2, 8, 6]

    S0 = [
            [1, 0, 3, 2], 
            [3, 2, 1, 0], 
            [0, 2, 1, 3], 
            [3, 1, 3, 2]
        ]
    
    S1 = [
            [0, 1, 2, 3], 
            [2, 0, 1, 3], 
            [3, 0, 1, 0], 
            [2, 1, 0, 3]
        ]
    
    def __init__(self, key, data) :
        self.setKey(key)
        self.setData(data)
    
    def setData(self, data) :
        self.data = data
    
    def setKey(self, key) :
        self.key = key
    
    def getData(self) :
        return self.data
    
    def getKey(self) :
        return self.key
    
    def encrypt(self) :
        key1, key2 = self.generateKey()

        result = ""
        print("[+] Start S-DES Encrypt")

        print("[+] Round 1 Start")
        print("[+] Input Plaintext : " + self.getData())
        # IP
        for element in self.IP :
            result += self.getData()[element - 1]
        
        print(f"[-] IP Stage : {result}")

        IP_High = result[:4]
        IP_Low = result[4:]

        # EP
        result = ""
        for element in self.EP :
            result += IP_Low[element - 1]
        
        print(f"[-] EP Stage : {result}")

        # XOR
        print(f"[-] XOR Stage : {result} ^ {key1}(key1)")
        result = bin(int(result, 2) ^ int(key1,2))[2:]
        result = (8 - len(result)) * "0" + result
        print(f"[-] XOR Stage : {result}")
        #print(result)

        row, column = self.getIndex(result[:4])
        row2, column2 = self.getIndex(result[4:])

        print(f"[-] Find Index : S0[{row}, {column}] = {bin(self.S0[row][column])[2:]}(2)")
        print(f"[-] Find Index : S1[{row2}, {column2}] = {bin(self.S1[row2][column2])[2:]}(2)")
        s_0 = bin(self.S0[row][column])[2:]
        s_1 = bin(self.S1[row2][column2])[2:]
        if len(s_0) == 1 : s_0 = "0" + s_0
        if len(s_1) == 1 : s_1 = "0" + s_1
        result = s_0 + s_1
        print(f"[-] Concat result : {result}")

        # P4
        P4_result = ""
        for element in self.P4 :
            P4_result += result[element - 1]
        
        print(f"[-] P4 Apply : {P4_result}")
        
        # XOR
        result = bin(int(P4_result, 2) ^ int(IP_High, 2))[2:]
        result = (4 - len(result)) * "0" + result
        print(f"[-] XOR IP_High(4bit) : {P4_result} ^ {IP_High} = {result}")

        result += IP_Low
        print(f"[-] Concat IP_Low(4bit) : {IP_Low}(IP_Low) => {result}")

        # Switch
        result = result[4:] + result[:4]
        print(f"[-] Switch Low <-> High : {result}")
        
        ####################################

        # Round 2
        print("\n[+] Round 2 Start")
        SW_High = result[:4]
        SW_Low = result[4:]

        result = ""
        for element in self.EP :
            result += SW_Low[element - 1]
        print(f"[-] EP Stage : {result}")

        # XOR Key2
        print(f"[-] XOR Stage : {result} ^ {key2}(key2)")
        result = bin(int(result, 2) ^ int(key2, 2))[2:]
        print(f"[-] XOR Stage : {result}")

        # getIndex
        row, column = self.getIndex(result[:4])
        row2, column2 = self.getIndex(result[4:])
        print(f"[-] Find Index : S0[{row}, {column}] = {bin(self.S0[row][column])[2:]}(2)")
        print(f"[-] Find Index : S1[{row2}, {column2}] = {bin(self.S1[row2][column2])[2:]}(2)")

        s_0 = bin(self.S0[row][column])[2:]
        s_1 = bin(self.S1[row2][column2])[2:]
        if len(s_0) == 1 : s_0 = "0" + s_0
        if len(s_1) == 1 : s_1 = "0" + s_1
        result = s_0 + s_1
        print(f"[-] Concat result : {result}")

        # P4
        P4_result = ""
        for element in self.P4 :
            P4_result += result[element - 1]
        print(f"[-] P4 Apply : {P4_result}")
        
        # XOR
        result = bin(int(P4_result, 2) ^ int(SW_High, 2))[2:]
        result = (4 - len(result)) * "0" + result
        print(f"[-] XOR SW_High(4bit) : {P4_result} ^ {SW_High}(SW_High) = {result}")

        # IP -1
        temp = result + SW_Low
        print(f"[-] Concat SW_Low(4bit) : {result} + {SW_Low}(SW_Low) = {temp}")
        result = ""
        for element in self.IP_1 :
            result += temp[element - 1]
        print(f"[-] IP^-1 Apply : {result}")
        
        return result

    def decrypt(self) :
        key1, key2 = self.generateKey()
        result = ""
        print("[+] Start S-DES Decrypt")
        print("[+] Round 1 Start")
        print("[+] Input Cipher : " + self.getData())

        # IP
        for element in self.IP :
            result += self.getData()[element - 1]
        
        print(f"[-] IP Stage : {result}")

        IP_High = result[:4]
        IP_Low = result[4:]

        # EP
        result = ""
        for element in self.EP :
            result += IP_Low[element - 1]
        
        print(f"[-] EP Stage : {result}")

        # XOR
        print(f"[-] XOR Stage : {result} ^ {key2}(key2)")
        result = bin(int(result, 2) ^ int(key2,2))[2:]
        result = (8 - len(result)) * "0" + result
        print(f"[-] XOR Stage : {result}")

        row, column = self.getIndex(result[:4])
        row2, column2 = self.getIndex(result[4:])
        print(f"[-] Find Index : S0[{row}, {column}] = {bin(self.S0[row][column])[2:]}(2)")
        print(f"[-] Find Index : S1[{row2}, {column2}] = {bin(self.S1[row2][column2])[2:]}(2)")
        
        s_0 = bin(self.S0[row][column])[2:]
        s_1 = bin(self.S1[row2][column2])[2:]
        if len(s_0) == 1 : s_0 = "0" + s_0
        if len(s_1) == 1 : s_1 = "0" + s_1
        result = s_0 + s_1
        print(f"[-] Concat result : {result}")
        
        # P4
        P4_result = ""
        for element in self.P4 :
            P4_result += result[element - 1]
        print(f"[-] P4 Apply : {P4_result}")
        
        # XOR
        result = bin(int(P4_result, 2) ^ int(IP_High, 2))[2:]
        print(f"[-] XOR IP_High(4bit) : {P4_result} ^ {IP_High}(IP_High) = {result}")

        result += IP_Low
        print(f"[-] Concat IP_Low(4bit) : {IP_Low}(IP_Low) => {result}")

        # Switch
        result = result[4:] + result[:4]
        print(f"[-] Switch Low <-> High : {result}")
        ####################################

        # Round 2
        print("\n[+] Round 2 Start")

        SW_High = result[:4]
        SW_Low = result[4:]

        result = ""
        for element in self.EP :
            result += SW_Low[element - 1]

        print(f"[-] EP Stage : {result}")
        

        # XOR Key1
        print(f"[-] XOR Stage : {result} ^ {key1}(key1)")
        result = bin(int(result, 2) ^ int(key1, 2))[2:]
        result = (8 - len(result)) * "0" + result
        print(f"[-] XOR Stage : {result}")

        # getIndex
        row, column = self.getIndex(result[:4])
        row2, column2 = self.getIndex(result[4:])

        print(f"[-] Find Index : S0[{row}, {column}] = {bin(self.S0[row][column])[2:]}(2)")
        print(f"[-] Find Index : S1[{row2}, {column2}] = {bin(self.S1[row2][column2])[2:]}(2)")

        s_0 = bin(self.S0[row][column])[2:]
        s_1 = bin(self.S1[row2][column2])[2:]
        if len(s_0) == 1 : s_0 = "0" + s_0
        if len(s_1) == 1 : s_1 = "0" + s_1
        result = s_0 + s_1
        print(f"[-] Concat result : {result}")

        # P4
        P4_result = ""
        for element in self.P4 :
            P4_result += result[element - 1]
        
        print(f"[-] P4 Apply : {P4_result}")
        
        # XOR
        result = bin(int(P4_result, 2) ^ int(SW_High, 2))[2:]
        print(f"[-] XOR IP_High(4bit) : {P4_result} ^ {SW_High}(SW_High) = {result}")

        # IP -1
        temp = result + SW_Low
        print(f"[-] Concat SW_Low(4bit) : {SW_Low}(SW_Low) => {temp}")

        result = ""
        for element in self.IP_1 :
            result += temp[element - 1]
        print(f"[-] IP^-1 Apply : {result}")
        return result
    
    def getIndex(self, data) :
        return int(data[0] + data[3], 2), int(data[1] + data[2], 2)
    
    def generateKey(self) :
        print("[+] Start Key Generate")
        result = ""
        # P10
        for element in self.P10 :
            result += self.key[element - 1]

        print(f"[-] P10 Apply : {result}")
        
        # LS1
        LS1_LeftData = self.LS1(result[:5])
        LS1_RightData = self.LS1(result[5:])

        result = LS1_LeftData + LS1_RightData
        print(f"[-] Left Shift 1 Apply : {result}")

        # P8
        Key1 = ""
        for element in self.P8 :
            Key1 += result[element - 1]
        
        print(f"[-] P8 Apply => getKey1 : {Key1}")
        
        #print(Key1)

        # LS2
        LS2_LeftData = self.LS2(LS1_LeftData)
        LS2_RightData = self.LS2(LS1_RightData)

        result = LS2_LeftData + LS2_RightData
        print(f"[-] Left Shift 2 Apply : {result}")

        # P8
        Key2 = ""
        for element in self.P8 :
            Key2 += result[element - 1]
        print(f"[-] P8 Apply => getKey2 : {Key2}")
        print(f"[+] Key1 = {Key1}, Key2 = {Key2}")
        print("")


        return Key1, Key2
        
    def LS1(self, data) :
        return data[1:] + data[0]
    
    def LS2(self, data) :
        return data[2:] + data[:2]

if __name__ == "__main__" :
    s = sdes('0110101001', '00001010')#'11010100')
    print(s.decrypt())