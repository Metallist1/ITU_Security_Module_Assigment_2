
import { createRequire } from 'module'
const require = createRequire(import.meta.url);

import { wrap_gen_sha_215, wrap_generate_sha_512 , wrap_verify_mac,wrap_gen_random_string,record_round, get_round } from './BLL/wrapper.js'
import { generate_random_string, pick_winner, verify_correctness } from './Helper/cipher_help.js'

// Socket setup
import { readFileSync } from "fs";
import { createServer } from "https";
import { Server } from "socket.io";

const PORT = process.env.PORT || 3000;

const httpServer = createServer({
  key: readFileSync("certificates/certs/server/server.key"),
  cert: readFileSync("certificates/certs/server/server.crt"),
  ca: readFileSync('certificates/certs/ca/ca.crt'), // authority chain for the clients
  requestCert: true, // ask for a client cert
});

const io = new Server(httpServer);

io.engine.on("connection", (rawSocket) => {
  rawSocket.peerCertificate = rawSocket.request.client.getPeerCertificate();
});

const max_rounds = 6

let secret_key = ""
let generated_sha_216_key = ""

let bobs_encrypted_key = "";
let picked_secret = "";


io.on("connection", (socket) => {
    console.log("Made socket connection");
    socket.on('start_round', (data) => {
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
                    socket.emit("sha_256_key",  sha_256_key);
                    generated_sha_216_key= sha_256_key.key;
                }
            });
        });

    });

    socket.on('GG', function (data) {
        console.log("Good Game")
        io.close() 
    });

    socket.on('compromised', function (data) {
        console.log("The connection is compromised")
        io.close() 
    });

    socket.on('sha_256_key', function (data) {

        console.log('Got Sha 256 key from Bob :', data.key);
        bobs_encrypted_key = data.key;

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
                    io.close()       
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
                    console.log('Got Sha 512 key from Bob :', data.key);

                    console.log("Roll is :" + pick_winner(data.key, 0 , 5))
            

                    const isFair = verify_correctness(data.key,bobs_encrypted_key,data.secret_key,picked_secret);
                    console.log("Was it fair ? " + isFair)
                    if(!isFair){
                        socket.emit("compromised", {data});
                        io.close()     
                    }
                }else{
                    socket.emit("compromised", {data});
                    io.close()      
                }
            }
        }); 
    });

    socket.on('random_string', (data) => {
        wrap_verify_mac(data, function(err, is_friend) {
            if (err){
                console.log(err);
                socket.emit("get_user_error", err);
            }
            else{
                if(is_friend){
                    wrap_generate_sha_512({secret_key:secret_key, bobs_key: data.key}, function(err, result_key) {
                        if (err){
                            console.log(err);
                            socket.emit("get_user_error", err);
                        }
                        else{ 
                            socket.emit("sha_512_key", result_key);
    
                            console.log("Roll is: " + pick_winner(result_key.key, 0 , 5))

                            const isFair = verify_correctness(result_key.key,generated_sha_216_key,secret_key,data.key);
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
                                            io.close();
                                        }
                                    }
                                });
                            }else{
                                socket.emit("compromised", {data});
                                io.close()  
                            }
                        }
                    });
                }else{
                    socket.emit("compromised", {data});
                    io.close()     
                }
            }
        }); 
    });

    socket.on("disconnect", () => {
        console.log("User disconnect");
    });

});

httpServer.listen(PORT, (err) => {
    if (err) {
        console.error(err);
    } else {
        console.info(`Server is running on port ${PORT}.`);
    }
});