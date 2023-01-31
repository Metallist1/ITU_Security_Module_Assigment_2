
import { createRequire } from 'module'
const require = createRequire(import.meta.url);

import { wrap_gen_sha_215, wrap_generate_sha_512 , wrap_verify_mac,wrap_gen_random_string,record_round, get_round } from './BLL/wrapper.js'
import { generate_random_string,pick_winner,verify_correctness } from './Helper/cipher_help.js'


import { readFileSync } from "fs";
import { io } from "socket.io-client";
//Sockets
const socket = io("https://localhost:3000", {
    transports: ['websocket'], 
    key: readFileSync('certificates/certs/client/client.key'),
    cert: readFileSync('certificates/certs/client/client.crt'),
    ca: [
        readFileSync('certificates/certs/ca/ca.crt')
      ]
   });

socket.on("connect_error", (err) => {
  console.log(`connect_error due to ${err.message}`);
});

const max_rounds = 6

function randomIntFromInterval(min, max) { // min and max included 
    return Math.floor(Math.random() * (max - min + 1) + min)
  }
let isCompromisedExternal = false
let isCompromisedInternal = false
let secret_key = ""
let generated_sha_216_key = ""

let alices_encrypted_key = "";
let picked_secret = "";

socket.on('connect', () => {
    console.log('Connected To Alice');

    get_round("", function(err, round) {
        if (err){
            console.log(err);
            socket.emit("get_user_error", err);
        }
        else{
            socket.emit("start_round", round);
        }
    });

    socket.on('start_round', (data) => {
        // Each round. There is a chance that this person might be compromised externally or is trying to cheat.

        const rndInt = randomIntFromInterval(1, 10)
        if(rndInt>=9){
            const typeOfCompromise = randomIntFromInterval(1, 4)
            if( typeOfCompromise >=2){
                console.log("My connection is highjacked");
                isCompromisedExternal=true;
            }else{
                console.log("I want to cheat");
                isCompromisedInternal=true;
            }
        }

        record_round(data, function(err, none) {
            generate_random_string(10, function(err, secret_string) {
                if (err){
                    console.log(err);
                    socket.emit("get_user_error", err);
                }
                else{
                    secret_key = secret_string;
                }
            });
        
            wrap_gen_sha_215(secret_key, function(err, sha_256_key) {
                if (err){
                    console.log(err);
                    socket.emit("get_user_error", err);
                }
                else{

                    generated_sha_216_key= sha_256_key.key;

                    if(isCompromisedExternal){
                        sha_256_key.key = "I am a third party"  
                    }

                    socket.emit("sha_256_key",  sha_256_key);

                }
            });
        });

    });

    socket.on('sha_256_key', function (data) {

        console.log('Got Sha 256 key from Alice :', data.key);
        alices_encrypted_key = data.key;

        wrap_verify_mac(data, function(err, is_friend) {
            if (err){
                console.log(err);
                socket.emit("get_user_error", err);
            }
            else{
                if(is_friend){
                    wrap_gen_random_string(10, function(err, secret_string) {
                        if (err){
                            console.log(err);
                            socket.emit("get_user_error", err);
                        }
                        else{
                            picked_secret = secret_string.key;
                            socket.emit("random_string",  secret_string);
                        }
                    });
                }else{
                    socket.emit("compromised", {data});      
                }
            }
        }); 
    });

    socket.on('sha_512_key', function (data) {
        wrap_verify_mac(data, function(err, isAlice) {
            if (err){
                console.log(err);
                socket.emit("get_user_error", err);
            }
            else{
                if(isAlice){
                    console.log('Got Sha 512 key from Alice :', data.key);

                    console.log("Roll is :" + pick_winner(data.key, 0 , 5))
            

                    const isFair = verify_correctness(data.key,alices_encrypted_key,data.secret_key,picked_secret);
                    console.log("Was it fair ? " + isFair)
                    if(!isFair){
                        socket.emit("compromised", {data});
                        socket.close()     
                    }
                }else{
                    socket.emit("compromised", {data});
                    socket.close()      
                }
            }
        }); 
    });

    socket.on('GG', function (data) {
        console.log("Good Game")
        socket.close() 
    });

    socket.on('compromised', function (data) {
        console.log("The game is compromised")
        socket.close() 
    });

    socket.on('random_string', (data) => {
        wrap_verify_mac(data, function(err, is_friend) {
            if (err){
                console.log(err);
                socket.emit("get_user_error", err);
            }
            else{
                if(is_friend){

                    let key_from_data = data.key
                    if(isCompromisedInternal){
                        key_from_data = "my pick :)"  
                    }

                    wrap_generate_sha_512({secret_key:secret_key, bobs_key: key_from_data}, function(err, result_key) {
                        if (err){
                            console.log(err);
                            socket.emit("get_user_error", err);
                        }
                        else{ 
                            socket.emit("sha_512_key", result_key);
    
                            console.log("Roll is: " + pick_winner(result_key.key, 0 , 5))
                            const isFair = verify_correctness(result_key.key,generated_sha_216_key,secret_key,key_from_data);
                            console.log("Was it fair ? " + isFair)
                            if(isFair){
                                get_round("", function(err, round) {
                                    if (err){
                                        console.log(err);
                                        socket.emit("get_user_error", err);
                                    }
                                    else{
                                        if(round +1 <= max_rounds){
                                            record_round(round+1, function(err, none) {
                                                socket.emit("start_round", round+1);
                                            });
                                        }else{
                                            console.log("GG")
                                            socket.emit("GG", {});
                                            socket.close()     
                                        }
                                    }
                                });
                            }else{
                                socket.emit("compromised", {data});
                                socket.close() 
                            }
                        }
                    });
                }else{
                    socket.emit("compromised", {data}); 
                    socket.close()      
                }
            }
        }); 
    });

});