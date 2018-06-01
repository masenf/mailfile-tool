import bottle
import dovepass

@bottle.get("/")
def make_form(err=None, addr=''):
    head = ["<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<title>Password Change</title>",
            "</head>",
            "<body>"]
    form = ["<form action='/password/chpass' method='POST'>",
            "<table>",
            "<tr>",
            "<td>Email address</td>",
            "<td><input type='text' name='addr' value='{}'></td>".format(addr),
            "</tr>",
            "<tr>",
            "<td>Old Password</td>",
            "<td><input type='password' name='oldpass'></td>",
            "</tr>",
            "<tr>",
            "<td>New Password</td>",
            "<td><input type='password' name='newpass'></td>",
            "</tr>",
            "<tr>",
            "<td>New Password (again)</td>",
            "<td><input type='password' name='vfypass'></td>",
            "</tr>",
            "<tr><td></td>",
            "<td><input type='submit' value='change'></td>",
            "</tr>",
            "</table>",
            "</form>"]
    foot = ["</body>",
            "</html>"]
    if err:
        head.append("<h2>{}</h2>".format(err))
    return "\n".join(head + form + foot)
@bottle.post("/chpass")
def chpass():
    addr = bottle.request.forms.get("addr")
    oldpass = bottle.request.forms.get("oldpass")
    newpass = bottle.request.forms.get("newpass")
    vfypass = bottle.request.forms.get("vfypass")

    try:
        user, domain = addr.split("@", 1)
    except ValueError:
        return make_form("Specify email as user@domain.tld")

    if newpass != vfypass:
        return make_form("New passwords do not match", addr)

    success, message = dovepass.chpass(user, domain, oldpass, newpass)

    if not success:
        return make_form("Error updating password: {}".format(message), addr)

    return "Password changed for user {}".format(addr)
if __name__ == "__main__":
    bottle.run(host="localhost", port="8952")
