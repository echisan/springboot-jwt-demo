package cn.echisan.springbootjwtdemo.repository;

import cn.echisan.springbootjwtdemo.entity.User;
import org.springframework.data.repository.CrudRepository;

public interface UserRepository extends CrudRepository<User, Integer> {
    User findByUsername(String username);
}
