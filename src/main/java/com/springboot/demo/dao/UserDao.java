package com.springboot.demo.dao;

import com.springboot.demo.domain.SysUser;


public interface UserDao {
    public SysUser findByUserName(String username);
}
