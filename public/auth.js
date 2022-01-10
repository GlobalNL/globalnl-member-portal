// setting up google login 
function googleLogin(){
    let provider = new firebase.auth.GoogleAuthProvider()
    console.log('login btn called')
    firebase.auth().signInWithPopup(provider).then(res => {
        const id_token = res.credential.idToken;
        console.log('here is the user token =>' + id_token)
        console.log('about to send token to the backend');
        checkAuthState()
    }).catch(e => {
        console.log(e)
    })
}

// setting up apple login
function appleLogin(){
    if (!firebase.auth().currentUser){
        let provider = new firebase.auth.OAuthProvider('apple.com');
        provider.addScope('email');
        provider.addScope('name');
        firebase.auth().signInWithPopup(provider).then (res => {
            const user = res.user;
            const id_token = res.credential.idToken;
            console.log('here is the user token =>' + id_token);
            console.log('about to send token to the backend');
            checkAuthState()
        }).catch(e => {
            console.log(e);
        })
    }
}

// setting up POST request to send the id_token to the backend
function checkAuthState(){
    console.log('id_token has been recieved')
    //getting the id_token of the currentUser
    firebase.auth().currentUser.getIdToken(true).then((id_token) => {
        // checking if user is authenticated
        firebase.auth().onAuthStateChanged(user => {
            if (user){
                console.log('user is authenticated')
                var xhr = new XMLHttpRequest();
                xhr.open('POST', '/login');
                xhr.setRequestHeader('Content-Type', 'application/json');
                xhr.onload = function (){
                    console.log('Status:' + xhr.responseText);
                    // if the user is authenticated, redirect them to the profile.html to finish setting up their account
                    if(xhr.responseText == 'success'){
                        location.reload();
                        initLoad();
                    }
                };
                xhr.send(JSON.stringify({
                    token: id_token
                }));
            }
            else{
                console.log('failed to authenticate/send data to backend')
            }
        })
    })
}