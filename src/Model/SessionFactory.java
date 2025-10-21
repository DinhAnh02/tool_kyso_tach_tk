package Model;

import API.ISessionFactory;
import API.IUserSession;
import API.Property;
import API.IServerSession;

public class SessionFactory implements ISessionFactory{
    private Property prop;
    private String lang;
    private String username;
    private String password;

    public SessionFactory(Property prop, String lang) {
        this.prop = prop;
        this.lang = lang;
    }
    
    public SessionFactory(Property prop, String lang, String username, String password) {
        this.prop = prop;
        this.lang = lang;
        this.username = username;
        this.password = password;
    }

    @Override
    public IServerSession getServerSession() {
        try {
            return new ServerSession(this.prop, this.lang, this.username, this.password);
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public IUserSession getUserSession(String username, String password) {
        return null;
    }

}
