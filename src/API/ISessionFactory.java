package API;

public interface ISessionFactory {

    //auth/login
    IServerSession getServerSession();

    //auth/login
    IUserSession getUserSession(String username, String password);
}
