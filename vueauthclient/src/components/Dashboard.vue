<template>
    <div>
        <h2>Dashboard</h2>
        <p>Name: {{ me.name }}</p>
        <p>Authorities: {{ me.authorities }}</p>
    </div>
</template>

<script>
/* eslint-disable */
import axios from 'axios'
import router from '../router'
export default {
    name: 'Login',
    data() {
        return {
            me: {
                name: 'Jesse'
            }
        }
    },
    methods: {
        getUserData: async function() {
            let self = this
            //console.log('>>', self.$get(this, 'token'))
            let token = localStorage.token
            console.log('>> token:', token)

            let res = await axios.get('/api/me', {headers:{Authorization:'Bearer ' + token}})

            console.log('>> ', res.data);

            self.$set(this, 'me', res.data)

            /*
            axios.get('/api/me')
                .then((response) => {
                    console.log(response)
                    self.$set(this, 'me', response.data.user)    
                })
                .catch((errors) => {
                    console.log(errors)
                    router.push('/')
                })
            */
        }
    },
    mounted() {
        this.getUserData()
    }
}
</script>
