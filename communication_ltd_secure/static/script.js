$(document).ready(function() {
    function initializeDataTable() {
        if (!$.fn.DataTable.isDataTable('#customerTable')) {
            $('#customerTable').DataTable({
                searching: false,
                lengthChange: false,
                autoWidth: false, // Disable automatic column width calculation
                responsive: true, // Enable responsive design
                columnDefs: [
                    { width: '20%', targets: 0 },
                    { width: '20%', targets: 1 },
                    { width: '60%', targets: 2 }
                ]
            });
        }
    }

    function initializeCharts() {
        if ($('#revenueChart').length) {
            var revenueCtx = document.getElementById('revenueChart').getContext('2d');
            var revenueChart = new Chart(revenueCtx, {
                type: 'line',
                data: {
                    labels: ['January', 'February', 'March', 'April', 'May', 'June'],
                    datasets: [{
                        label: 'Revenue',
                        data: [3200, 6200, 6300, 14700, 10000, 23000],
                        backgroundColor: 'rgba(75, 192, 192, 0.2)',
                        borderColor: 'rgba(75, 192, 192, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        yAxes: [{
                            ticks: {
                                beginAtZero: true
                            }
                        }]
                    }
                }
            });
        }

        if ($('#visitChart').length) {
            var visitCtx = document.getElementById('visitChart').getContext('2d');
            var visitChart = new Chart(visitCtx, {
                type: 'bar',
                data: {
                    labels: ['January', 'February', 'March', 'April', 'May', 'June'],
                    datasets: [{
                        label: 'New Customers',
                        data: [3200, 3000, 4000, 4500, 3700, 9000],
                        backgroundColor: 'rgba(89, 49, 168, 0.4)',
                        borderColor: 'rgba(153, 102, 255, 1)',
                        borderWidth: 1
                    }]
                },
                options: {
                    scales: {
                        yAxes: [{
                            ticks: {
                                beginAtZero: true
                            }
                        }]
                    }
                }
            });
        }
    }

    initializeDataTable();
    initializeCharts();
});
