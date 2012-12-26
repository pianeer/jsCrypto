/**
 * @author Nikhil Mohan
 */

var Signature=
{
    hmacObj: null
}

Signature.calcHMAC = function(input_text, input_type, key, key_type)
{    
    this.hmacObj = new jsSHA(input_text, input_type);
    var hmac = this.hmacObj.getHMAC(key, key_type, "SHA-256" , "HEX");
    if(hmac !== ""){
        return hmac;
    }
    return '';
}

Signature.get_decrypted_token = function(ivalue, token)
{
    //Generate token by decrypting values            
    var options = {A0_PAD:false, pkcs5:false};
    var aes = new pidCrypt.AES.CBC();
    aes.initByValues("", pidCryptUtil.convertToHex (Device.getSecret()), ivalue, options);
    var final_token = aes.decryptRaw(pidCryptUtil.toByteArray (pidCryptUtil.convertFromHex(token)));    
    return final_token;
}
