//Below is the unsecure code
//FilePathResult action result using the fileName request parameter to construct the file path location.
[HttpPost]
public FileResult Download(string fileName)
{
    string filePath = ConfigurationManager.AppSettings["DownloadDirectory"].ToString();
    return new FilePathResult(filePath + fileName, "application/octet-stream");  //Vulnerable
}

//Below is the secure code
[HttpPost]
public FileResult Download(Guid fileId)
{
    string filePath = ConfigurationManager.AppSettings["DownloadDirectory"].ToString();
    filePath = string.Format("{0}{1}.pdf", filePath, fileId.ToString());
    return new FilePathResult(filePath, "application/octet-stream");  //It will be detected as Vulnerable. 
}

//Below is the unsecure code
//FileStream being constructed from a dynamic parameter to determine the file path location and passed to FileStreamResult.
public ActionResult Index(string fileName)
{
    using (Stream stream = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))  //Vulnerable. 
    {
        return new FileStreamResult(stream, fileName);
    }
}

//Below is the secure code
public ActionResult Index(Guid fileId)
{
    string path = Path.Combine(ConfigurationManager.AppSettings["DownloadPath"], fileId.ToString());

    //NOTE: YOU MAY STILL NEED TO PERFORM ENTITLEMENT AUTHORIZATION BEFORE RETURNING THE FILE

    using (Stream stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read)) //It will be detected as Vulnerable. 
    {
        return new FileStreamResult(stream, fileName); //It will be detected as Vulnerable
    }
}

//Note: In case of secure code also, it will detect as Vulnerable. As we can't apply rules for the logic implemented for constructing file path. It can be read from trusted location like configutration file or static resource, through DB or can apply any logic to validate or sanitized path before sending it to action. But, Failing to validate the file path used by these actions can allow path traversal vulnerabilities.