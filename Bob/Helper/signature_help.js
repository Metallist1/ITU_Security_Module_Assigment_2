'use strict';
const { createHash, createHmac } = await import('node:crypto');

let verify_mac =  async function(key, result) {
    const auth_key = createHash('sha256').update(key.shared_secret + key.nounce).digest('hex')

    const hmac = createHmac('sha256', auth_key);
          
    hmac.update(key.message);
    if(hmac.digest('hex') == key.provided_sig){
        result(null, true);
    }else{
        result(null, false);
    }
};


let generate_mac =  async function(key, result) {

    const auth_key = createHash('sha256').update(key.shared_secret + key.nounce).digest('hex')

    const hmac = createHmac('sha256', auth_key);
          
    hmac.update(key.message);
    
    result(null, hmac.digest('hex'));
};

export {generate_mac, verify_mac};