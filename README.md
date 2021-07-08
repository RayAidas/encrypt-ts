## encript-ts 
>使用方法  

  import Encrypt from "yourpath/Encrypt";  

  const encrypt = new Encypt()  

  // 加密密钥  
  let secretkey= 'open_sesame';     

  let testData = "test";  

  // 加密  
  let encrypted = encrypt.encrypt(testData,secretkey,256);    
  
  // 存储
  localStorage.setItem('testData', encrypted);  

  // 读取   
  let cipherText = localStorage.getItem('testData');  

  let data = encrypt.decrypt(cipherText,secretkey,256);  

  console.log(data);

