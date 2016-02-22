<?php

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
class Auth{
    
    static $ci;
    public $tableName;
    public $role;
    private $activity_logs_table_name='activiy_logs';
    private $comment;
            
    function __construct(){
        self::$ci =& get_instance();
    }
    
    public function login_validataion()
    {
        if($this->tableName=='administrators'){
            $res = self::$ci->db->get_where($this->tableName,['email'=>  self::$ci->input->post('username'), 'status'=>'ACTIVE'])->row();
        }else{
            $res = self::$ci->db->get_where($this->tableName,['username'=>  self::$ci->input->post('username'), 'status'=>'ACTIVE'])->row();
        }
        if($res){
            //echo $res->password."<br/>";die;
            $password = md5(self::$ci->input->post('password').$res->salt);
            if($res->password!=$password){
                //return "INVALID_PASSWORD";
                return FALSE;
            }else if($res->password==$password){
                $res = self::$ci->db->get_where($this->tableName,['id'=>$res->id])->row();
                //echo self::$ci->db->last_query(); die;
                $this->set_role();
                $this->member_login_session_creation($res);
                return true;
            }
        }else{
            //echo "INVALID_USERNAME_OR_PASSWORD";
            return FALSE;
        }
    }    
    public function admin_validation(){
        $this->tableName='administrators';
        return $this->login_validataion();
    }
    
    public function member_login_session_creation($res){
        if($this->tableName=='administrators'){
            $username = $res->email;
        }else{
            $username=$res->username;
        }
        $user_data = array(
                'member_id' => $res->id, 
                'username' => $res->username,
                'email' => $res->email,
                'logged_in' => true,
            );
        self::$ci->session->set_userdata($user_data);
        $this->comment="Logged in";
        $this->create_activity_log();
    }
    
    public function set_role(){
        //1. super_admin
        //2. sub_admin
        //3. pharama_admin
        //4. delivery_boy
        //5. customer
        self::$ci->session->set_userdata('role',$this->role);
    }
    public function get_role(){
        return self::$ci->session->userdata('role');
    }
    public function create_activity_log(){
        $arr = array('user_id'=>self::$ci->session->userdata('member_id'),
                    'role_id'=>$this->get_role(),
                    'user_agent'=>  filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'),
                    'ip'=>  self::$ci->input->ip_address(),
                    'last_activity'=>time(),
                    'table_name'=>$this->tableName,
                    'comment'=>$this->comment);
        self::$ci->db->set($arr)->insert($this->activity_logs_table_name);
    }
    
    public function is_admin_logged(){
        if(self::$ci->session->userdata('logged_in') && self::$ci->session->userdata('role')==1){
            return true;
        }
        return false;
    }
    
    protected function logout(){
        $this->comment="Logged out";
        $this->activity_logs_table_name();
        $this->auth_unset_session();
    }
    
    public function auth_unset_session(){
        self::$ci->session->set_userdata('role','');
        $user_data = array(
                'member_id' => '', 
                'username' => '',
                'logged_in' => '',
                'email' => ''
            );
        self::$ci->session->set_userdata($user_data);
        self::$ci->session->sess_destroy();
    }
    
    public function get_member_details($id){
        return self::$ci->db->get_where($this->tableName,['id'=>$id])->result();
    }
    public function super_admin_login_id(){
        if(self::$ci->session->userdata('role')==1){
            return self::$ci->session->userdata('member_id');
        }
    }
    
    
    //for pharma
    public function pharma_admin_validation(){
        $this->tableName = 'pharamacy_users';
        return $this->login_validataion();
    }
    
    public function is_pharma_admin_logged(){
        if(self::$ci->session->userdata('logged_in') && self::$ci->session->userdata('role')==2){
            return true;
        }
        return false;
    }
    public function pharma_admin_login_id(){
        if(self::$ci->session->userdata('role')==2){
            return self::$ci->session->userdata('member_id');
        }
    }
    
    //for deliveryboy
    public function deliveryboy_validation(){
        //$this->tableName = 'pharamacy_users';
        return $this->login_validataion();
    }
    
    public function is_deliveryboy_logged(){
        if(self::$ci->session->userdata('logged_in') && self::$ci->session->userdata('role')==3){
            return true;
        }
        return false;
    }
    public function deliveryboy_login_id(){
        if(self::$ci->session->userdata('role')==3){
            return self::$ci->session->userdata('member_id');
        }
    }
} 