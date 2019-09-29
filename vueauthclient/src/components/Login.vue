<template>
    <div>
        <h2>Login</h2>
        <form v-on:submit="login">
            <input type="text" name="username" /><br>
            <input type="password" name="password" /><br>
            <input type="submit" value="Login" />
        </form>
    </div>
</template>

<script>
/* eslint-disable */
import router from '../router'
import axios from 'axios'
import xauth2 from 'xauth2'
var querystring = require('querystring');

export default {
  name: 'Login',
  methods: {
    auth: function() {
      this.$auth.authenticate('oauth2').then(()=> {
        console.log('>> auth successfull');
      })
    },
    login: async (e) => {
      e.preventDefault()
      let username = 'user'
      let password = '222'

      let res = await login(username, password)

      localStorage.token = res.access_token

      //this.$set(this, 'token', res)    

      router.push('/dashboard')
      
      /*
      let login = () => {
        let data = {
          grant_type: 'password',
          username: username,
          password: password
        }
        console.log('>> login:', data)
        axios.post('/api/login', data)
          .then((response) => {
            console.log('Logged in')
            router.push('/dashboard')
          })
          .catch((errors) => {
            console.log('Cannot log in')
          })
      }
      login()
      */

    }
  }
}

async function login(username, password) {
  let client_id = 'myclient'
  let client_secret = '222'
  let url = `http://localhost:9090/api/login`

  username = encodeURIComponent(username)
  password = encodeURIComponent(password)

  let data = `grant_type=password&username=${username}&password=${password}`
  let auth = btoa(unescape(client_id+':'+client_secret))
  let ret = await axios.post(url, data, {headers:{'Authorization': 'Basic '+auth, 'Content-Type':'application/x-www-form-urlencoded'}})

  console.log('>> access_token:', ret.data.access_token) 

  return ret.data;
}

</script>
