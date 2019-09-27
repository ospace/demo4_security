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
import router from '../router'
import axios from 'axios'
import xauth2 from 'xauth2'

export default {
  name: 'Login',
  methods: {
    auth: function() {
      this.$auth.authenticate('oauth2').then(()=> {
        console.log('>> auth successfull');
      })
    },
    login: (e) => {
      e.preventDefault()
      let username = 'user'
      let password = '222'
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
    }
  }
}
</script>
