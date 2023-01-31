import { generate_random_string,generate_sha_256,generate_sha_512 } from '../Helper/cipher_help.js'
import { generate_mac, verify_mac} from '../Helper/signature_help.js'

let agreed_secret = "SecretK"
let round = 1

let record_secret =  async function(secret, result) {
    agreed_secret = secret
    result(null, "done");
};

let get_round =  async function(none, result) {
    result(null, round);
};

let record_round =  async function(new_round, result) {
    round = new_round;
    result(null, "done");
};


let wrap_gen_sha_215 =  async function(key, result) {
    generate_sha_256(key, function(err, sha_256_key) {
        if (err){
            result(err, null);
        }
        else{
            
            const dataStruct = {
                key:sha_256_key
            }

            const msg = combine_message(dataStruct);

            generate_mac({shared_secret: agreed_secret,nounce:round,message: msg }, function(err, signature) {
                if (err){
                    result(err, null);
                }
                else{
                    dataStruct["signature"] = signature;
                    result(null, dataStruct);
                }
            }); 
        }
    });
};

let wrap_generate_sha_512 =  async function(event, result) {
    generate_sha_512(event, function(err, result_key) {
        if (err){
            result(err, null);
        }
        else{
            const dataStruct = {
                key:result_key,
                secret_key:event.secret_key
            }
            const msg = combine_message(dataStruct);
            generate_mac({shared_secret: agreed_secret, nounce:round, message: msg }, function(err, signature) {
                if (err){
                    result(err, null);
                }
                else{
                    dataStruct["signature"] = signature;
                    result(null, dataStruct);
                }
            }); 
        }
    });
};

let wrap_gen_random_string =  async function(length_of_string, result) {
    generate_random_string(length_of_string, function(err, secret_string) {
        if (err){
            result(err, null);
        }
        else{

            const dataStruct = {
                key:secret_string + round
            }
            const msg = combine_message(dataStruct);

            generate_mac({shared_secret: agreed_secret, nounce:round, message: msg }, function(err, signature) {
                if (err){
                    result(err, null);
                }
                else{
                    dataStruct["signature"] = signature;
                    result(null, dataStruct);
                }
            }); 
        }
    });
};

function combine_message (data){
    let message = '';
    Object.keys(data).forEach(function(key) {
        if(key != "signature")
            message = message + data[key];
      });
    return message;
}

let wrap_verify_mac =  async function(data, result) {
    let message = combine_message(data);

    verify_mac({shared_secret: agreed_secret, nounce:round, message: message, provided_sig: data.signature  }, function(err, is_friend) {
        if (err){
            result(err, null);
        }
        else{
            result(null, is_friend);
        }
    });
};


export {wrap_gen_random_string, wrap_gen_sha_215 , wrap_generate_sha_512, wrap_verify_mac, record_secret, record_round, get_round};