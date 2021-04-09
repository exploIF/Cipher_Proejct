# RSA cipher algorithm
Message sending simulator with cipher encryption and decryption based on RSA algorithm.

## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Features](#features)
* [Status](#status)
* [Inspiration](#inspiration)
* [Contact](#contact)

## General info
Project consisting of Python program simulating sending messages between users, fast API server, and some unit tests. Messages are encrypted with the RSA algorithm based on random primary numbers.


## Technologies
* Python - version 3.9
* Fast API - version 0.63

## Setup
Fast API server is protected using BasicAuth
* username: "exploIF"  
* password: "synapsi.xyz"

## Features
* Python program.
* Some basic unit tests.
* Fast API server.
* Based on RSA algorithm.
* Users accounts with private and public keys.
* Works with escape characters, punctuation marks, new lines, and tabs.
* Encrypting and decrypting polish special characters.
* Docker image for FastAPI server.

### To-do list:
* Add compression method to stored coded messages.
* Contenerize with docker.

## Status
Project is: finished

## Inspiration
Project made as a recruitment task for synapsi.xyz

## Contact
Created by [@exploIF](https://github.com/exploIF) - feel free to contact me!
