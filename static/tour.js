$(document).ready(function(){
    $('#date').keyup(function(){
        var data = $("#addTour").serialize()   // capture all the data in the form in the variable data
        $.ajax({
            method: "POST",   // we are using a post request here, but this could also be done with a get
            url: "/date",
            data: data
        })
        .done(function(res){
             $('#dateMsg').html(res)  // manipulate the dom when the response comes back
        })
    })
})