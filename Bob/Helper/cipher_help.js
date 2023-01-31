'use strict';
const { createHash } = await import('node:crypto');
/*

const { createHmac } = await import('node:crypto');

const secret = 'abcdefg';
const hash = createHmac('sha256', secret)
               .update('I love cupcakes')
               .digest('hex');
console.log(hash);

crypto.createHash('sha512').update('my string for hashing').digest('hex');
*/
let generate_sha_256 =  async function(key, result) {
    result(null, createHash('sha256').update(key).digest('hex'));
};

let generate_sha_512 =  async function(event, result) {
    const salted_string = event.secret_key + event.bobs_key
    result(null, createHash('sha512').update(salted_string).digest('hex'));
};

let generate_random_string =  async function(event, result) {
    var result_string           = '';
    var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var charactersLength = characters.length;
    for ( var i = 0; i < event; i++ ) {
      result_string += characters.charAt(Math.floor(Math.random() * 
 charactersLength));
   }
    result(null, result_string);
};

function pick_winner(hash, start , end) { 
    const game_pick = hash.substring(start, end)
    let int_to_check = parseInt(game_pick, 16)
    if (int_to_check >= 1_000_000 || int_to_check < 0){
        return pick_winner(hash, start + 1, end + 1)
    }
    else{
        const reminder = int_to_check % 10000
        const pick = Math.round(reminder / 1000)
        if (pick > 6 || pick < 0){
            return pick_winner(hash, start + 1, end + 1)
        }

        return pick;
    }
}

function verify_correctness(sha_512, sha_216 , gotten_secret_key, picked_string) { 
    
    const sha_to_check = createHash('sha256').update(gotten_secret_key).digest('hex')
    const salted_string = gotten_secret_key + picked_string
    const sha_512_to_check = createHash('sha512').update(salted_string).digest('hex')

    if( sha_216 == sha_to_check && sha_512 == sha_512_to_check){
        return true;
    }else{
        return false;
    }
}

export {generate_sha_256, generate_sha_512, generate_random_string, pick_winner, verify_correctness};