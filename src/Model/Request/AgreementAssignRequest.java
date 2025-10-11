package Model.Request;

import Model.Enum.UserType;

public class AgreementAssignRequest extends Request {
    public String agreementUUID;
    public String user;
    // [JsonConverter(typeof(StringEnumConverter))] -> chua lam
    public UserType userType; //UserType nam trong Types.cs
    public String authorizeCode;
}
