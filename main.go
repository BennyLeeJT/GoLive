package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

var tmpl *template.Template
var mapUsers = map[string]user{}
var mapSessions = map[string]string{}

// var db *sql.DB

type user struct {
	Username string
	Password []byte
	First    string
	Last     string
}

type CarparkJSONStruct struct {
	Items []struct {
		Timestamp   time.Time `json:"timestamp"`
		CarparkData []struct {
			CarparkInfo []struct {
				TotalLots     string `json:"total_lots"`
				LotType       string `json:"lot_type"`
				LotsAvailable string `json:"lots_available"`
			} `json:"carpark_info"`
			CarparkNumber  string `json:"carpark_number"`
			UpdateDatetime string `json:"update_datetime"`
		} `json:"carpark_data"`
	} `json:"items"`
}

// INIT & MAIN
func init() {
	// fmt.Println("start of func init")

	bPassword, _ := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	mapUsers["admin"] = user{"admin", bPassword, "admin", "admin"}

	// fmt.Printf("mapUsers : %v \n\n", mapUsers) // slice of bytes
	// fmt.Println("end of func init")
}

func main() {
	// fmt.Println("start of func main")

	tmpl = template.Must(template.ParseGlob("templates/*"))

	http.HandleFunc("/", index)
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/userDetailsInfo", userDetailsInfo)
	http.HandleFunc("/carparkInfo", carparkInfo)
	http.HandleFunc("/carparkAddress", carparkAddress)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)

	http.ListenAndServe(":3300", nil)
}

// CODES ON HTML PAGES
func index(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	tmpl.ExecuteTemplate(res, "index.gohtml", myUser)
}

func userDetailsInfo(res http.ResponseWriter, req *http.Request) {
	myUser := getUser(res, req)
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	tmpl.ExecuteTemplate(res, "userDetailsInfo.gohtml", myUser)
}

func signup(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	var myUser user
	// process form submission
	if req.Method == http.MethodPost {
		// get form values
		username := req.FormValue("username")
		password := req.FormValue("password")
		firstname := req.FormValue("firstname")
		lastname := req.FormValue("lastname")
		if username != "" {
			// check if username exist/ taken
			if _, ok := mapUsers[username]; ok {
				http.Error(res, "Username already taken", http.StatusForbidden)
				return
			}
			// create session
			id, _ := uuid.NewV4()
			myCookie := &http.Cookie{
				Name:  "myCookie",
				Value: id.String(),
			}
			http.SetCookie(res, myCookie)
			mapSessions[myCookie.Value] = username

			bPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				http.Error(res, "Internal server error", http.StatusInternalServerError)
				return
			}

			myUser = user{username, bPassword, firstname, lastname}
			mapUsers[username] = myUser
		}
		// redirect to main index
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return

	}
	tmpl.ExecuteTemplate(res, "signup.gohtml", myUser)
}

func login(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	// process form submission
	if req.Method == http.MethodPost {
		username := req.FormValue("username")
		password := req.FormValue("password")
		// check if user exist with username
		myUser, ok := mapUsers[username]
		if !ok {
			http.Error(res, "Username and/or password do not match", http.StatusUnauthorized)
			return
		}
		// Matching of password entered
		err := bcrypt.CompareHashAndPassword(myUser.Password, []byte(password))
		if err != nil {
			http.Error(res, "Username and/or password do not match", http.StatusForbidden)
			return
		}
		// create session
		id, _ := uuid.NewV4()
		myCookie := &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}
		fmt.Printf("myCookie when login post method : %v", myCookie)
		http.SetCookie(res, myCookie)
		mapSessions[myCookie.Value] = username
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}

	tmpl.ExecuteTemplate(res, "login.gohtml", nil)
}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	myCookie, _ := req.Cookie("myCookie")
	// delete the session
	delete(mapSessions, myCookie.Value)
	// remove the cookie
	myCookie = &http.Cookie{
		Name:   "myCookie",
		Value:  "",
		MaxAge: -1,
	}
	http.SetCookie(res, myCookie)

	http.Redirect(res, req, "/", http.StatusSeeOther)
}

// END OF CODES ON HTML FILES

func getUser(res http.ResponseWriter, req *http.Request) user {
	// get current session cookie
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		id, _ := uuid.NewV4()
		myCookie = &http.Cookie{
			Name:  "myCookie",
			Value: id.String(),
		}
	}
	http.SetCookie(res, myCookie)

	// just to check, it will break the html because these will be the starting codes
	// io.WriteString(res, myCookie.Name+"\n")
	// io.WriteString(res, myCookie.Value)
	fmt.Println(myCookie) // shown in debug console

	// if the user exists already, get user
	var myUser user
	if username, ok := mapSessions[myCookie.Value]; ok {
		myUser = mapUsers[username]
	}

	return myUser
}

func alreadyLoggedIn(req *http.Request) bool {
	myCookie, err := req.Cookie("myCookie")
	if err != nil {
		return false
	}
	username := mapSessions[myCookie.Value]
	_, ok := mapUsers[username]
	return ok
}

func carparkInfo(res http.ResponseWriter, req *http.Request) {
	allCarParkInfo := getAllCarParkInfo(res, req)
	tmpl.ExecuteTemplate(res, "carparkInfo.gohtml", allCarParkInfo)
}

func getAllCarParkInfo(res http.ResponseWriter, req *http.Request) CarparkJSONStruct {
	apiResponse, err := http.Get("https://api.data.gov.sg/v1/transport/carpark-availability")

	// if using manual created JSON string
	// apiResponse := `{
	// 	"items":
	// 	[
	// 		{
	// 		"timestamp": "2021-05-12T03:41:27+08:00",
	// 		"carpark_data": [
	//   						{"carpark_info":[
	// 							  			{"total_lots":"500",
	// 										"lot_type":"C",
	// 										"lots_available":"499"
	// 										}],
	// 						"carpark_number":"B8B",
	// 						"update_datetime":"2021-05-13T05:22:00"
	// 						}
	//   						]
	// 		}
	// 	]}`

	if err != nil {
		fmt.Printf("HTTP request failed with error %s\n", err)
		panic(err.Error())
	}

	APIJSONData, _ := ioutil.ReadAll(apiResponse.Body)

	// fmt.Printf("APIJSONData : %v\n\n", APIJSONData) // slice of bytes produced
	// APIJSONDataString := string(APIJSONData) // convert to string
	// fmt.Printf("APIJSONData : %v\n\n", APIJSONDataString) // print as string

	var carparkFullData CarparkJSONStruct

	err = json.Unmarshal(APIJSONData, &carparkFullData)
	if err != nil {
		fmt.Println(err)
	}

	carparkSlice := carparkFullData.Items[0].CarparkData
	// fmt.Printf("carparkSlice : %v\n\n", carparkSlice)
	// fmt.Printf("%T\n\n", carparkSlice) // slice of structs

	for i := range carparkSlice {
		fmt.Printf("%+v\n", carparkSlice[i])
	}

	return carparkFullData

}

// CSVFileToMap  reads csv file into slice of map
// slice is the line number
// map[string]string where key is column name
func CSVFileToMap(filePath string) (returnMap []map[string]string, err error) {

	// read csv file
	csvfile, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	defer csvfile.Close()

	reader := csv.NewReader(csvfile)

	rawCSVdata, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	header := []string{} // holds first row (header)
	for lineNum, record := range rawCSVdata {

		// for first row, build the headers in the slice
		if lineNum == 0 {
			for i := 0; i < len(record); i++ {
				header = append(header, strings.TrimSpace(record[i]))
			}
		} else {
			// for each cell, map[string]string key=header value=value
			line := map[string]string{}
			for i := 0; i < len(record); i++ {
				line[header[i]] = record[i]
			}
			returnMap = append(returnMap, line)
		}
	}

	for i := range returnMap {
		fmt.Printf("%v \n", returnMap[i])
	}

	return
}

func carparkAddress(res http.ResponseWriter, req *http.Request) {
	CSVFileToMap("carpark-information-BL.csv")
	tmpl.ExecuteTemplate(res, "carparkAddress.gohtml", nil)
}
